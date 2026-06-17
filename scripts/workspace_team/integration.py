"""
Workspace team (M×N) — INTEGRATION variant.

Maps to blog section 2.3 "Workspace team (M×N) — need-to-know access to workspace"
for the integration workload: ingest from an on-prem / Azure SQL source through
the OPDG and land Parquet on ADLS Gen2.

Steps:
  3.1  Create the SQL source connection on the OPDG (3.1a) and the ADLS Gen2 target
       ShareableCloud connection (3.1b). Credentials pulled from Key Vault.
  3.2  Create / update the Fabric copy pipeline (SQL -> Parquet).
  3.3  Trigger the pipeline run and poll until it finishes.

Step 3.1 auto-retries POST /connections on transient upstream-data-source errors
(e.g. Azure SQL serverless DB resuming from pause, gateway DataSourceAccessError)
with 10s / 30s / 60s backoff before bailing out.

Auth: `az login --service-principal --username <team-app-id>` for a Team SPN that
is a member of team_workspace_contributor_security_group (granted access by the
integration platform team in step 2.2 + 2.3).

Usage:
    python scripts/workspace_team/integration.py 3   config/workspace_team/integration/prod-01.yaml
    python scripts/workspace_team/integration.py 3.1 config/workspace_team/integration/prod-01.yaml
    python scripts/workspace_team/integration.py 3.2 config/workspace_team/integration/prod-01.yaml
    python scripts/workspace_team/integration.py 3.3 config/workspace_team/integration/prod-01.yaml
    python scripts/workspace_team/integration.py status config/workspace_team/integration/prod-01.yaml
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _fabric_common import (  # noqa: E402
    FabricClient,
    create_connection,
    find_connection,
    find_pipeline,
    find_workspace,
    load_config,
    require_connection,
    require_identity,
    require_workspace,
    resolve_gateway_id,
    step_log,
)


# --- Step 3.1: connections (OPDG SQL source + ShareableCloud ADLS target) ---


def step_3_1a(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    return create_connection(
        client, cfg, cfg["connections"]["source"],
        resolve_gateway_id(client, cfg, "opdg", "3.1a"),
        "OnPremisesGateway", "3.1a",
    )


def step_3_1b(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    # The VDG ADLS connector does not support WorkspaceIdentity (only Key/OAuth2/SAS/SP).
    # WorkspaceIdentity is supported only on ShareableCloud. We create a cloud connection
    # with allowConnectionUsageInGateway=true so it can be consumed by pipeline activities
    # that route through the OPDG/VDG that the workspace has access to. The VDG id is
    # resolved here only to validate the workspace can see it.
    resolve_gateway_id(client, cfg, "vdg", "3.1b")
    return create_connection(
        client, cfg, cfg["connections"]["target"],
        None, "ShareableCloud", "3.1b",
        allow_connection_usage_in_gateway=True,
    )


def step_3_1(client: FabricClient, cfg: dict[str, Any]) -> None:
    step_3_1a(client, cfg)
    step_3_1b(client, cfg)


# --- Step 3.2: copy pipeline (SQL -> Parquet) -----------------------------


def build_pipeline_definition(
    src_conn_id: str, src_query: str,
    tgt_conn_id: str, tgt_path: str, tgt_file_name: str,
) -> dict[str, Any]:
    pipeline = {
        "properties": {
            "activities": [
                {
                    "name": "CopySqlToParquet",
                    "type": "Copy",
                    "typeProperties": {
                        "source": {
                            "type": "AzureSqlSource",
                            "sqlReaderQuery": src_query,
                            "queryTimeout": "02:00:00",
                            "partitionOption": "None",
                            "datasetSettings": {
                                "type": "AzureSqlTable",
                                "schema": [],
                                "externalReferences": {"connection": src_conn_id},
                            },
                        },
                        "sink": {
                            "type": "ParquetSink",
                            "storeSettings": {"type": "AzureBlobFSWriteSettings"},
                            "formatSettings": {"type": "ParquetWriteSettings"},
                            "datasetSettings": {
                                "type": "Parquet",
                                "typeProperties": {
                                    "location": {
                                        "type": "AzureBlobFSLocation",
                                        "folderPath": tgt_path,
                                        "fileName": tgt_file_name,
                                    },
                                    "compressionCodec": "snappy",
                                },
                                "externalReferences": {"connection": tgt_conn_id},
                            },
                        },
                        "enableStaging": False,
                        "translator": {"type": "TabularTranslator", "typeConversion": True},
                    },
                }
            ]
        }
    }
    payload = base64.b64encode(json.dumps(pipeline).encode("utf-8")).decode("ascii")
    return {"parts": [{"path": "pipeline-content.json", "payload": payload, "payloadType": "InlineBase64"}]}


def step_3_2(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    ws = require_workspace(client, cfg, "3.2")
    src_conn = require_connection(client, cfg["connections"]["source"]["name"], "3.2")
    tgt_conn = require_connection(client, cfg["connections"]["target"]["name"], "3.2")
    name = cfg["pipeline"]["name"]
    definition = build_pipeline_definition(
        src_conn["id"], cfg["pipeline"]["source_query"],
        tgt_conn["id"], cfg["pipeline"].get("target_path") or "",
        cfg["pipeline"].get("target_file_name") or "output.parquet",
    )
    existing = find_pipeline(client, ws["id"], name)
    if existing:
        client.post(
            f"/workspaces/{ws['id']}/dataPipelines/{existing['id']}/updateDefinition",
            {"definition": definition},
        )
        step_log("3.2", f"Updated pipeline '{name}' (id={existing['id']})")
        return existing
    item = client.post(
        f"/workspaces/{ws['id']}/items",
        {"displayName": name, "type": "DataPipeline", "definition": definition},
    )
    step_log("3.2", f"Created pipeline '{name}' (id={item.get('id')})")
    return item


# --- Step 3.3: trigger and poll ------------------------------------------


def step_3_3(client: FabricClient, cfg: dict[str, Any], timeout: int) -> str:
    ws = require_workspace(client, cfg, "3.3")
    pipeline = find_pipeline(client, ws["id"], cfg["pipeline"]["name"])
    if not pipeline:
        raise SystemExit(f"[3.3] Pipeline '{cfg['pipeline']['name']}' not found. Run step 3.2 first.")
    resp = client.request(
        "POST", f"/workspaces/{ws['id']}/items/{pipeline['id']}/jobs/instances?jobType=Pipeline"
    )
    location = resp.headers.get("Location")
    if not location:
        raise RuntimeError("Pipeline run did not return a Location header to poll")
    step_log("3.3", f"Pipeline run triggered; polling {location}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        status_obj = client.get(location)
        status = status_obj.get("status", "Unknown")
        step_log("3.3", f"  status={status}")
        if status in {"Completed", "Failed", "Cancelled", "Deduped"}:
            step_log("3.3", f"Pipeline final status: {status}")
            if status != "Completed":
                fr = status_obj.get("failureReason") or {}
                if fr:
                    step_log("3.3", f"  errorCode={fr.get('errorCode')}")
                    step_log("3.3", f"  message={fr.get('message')}")
                step_log("3.3", f"  full job instance: {json.dumps(status_obj, indent=2)}")
            return status
        time.sleep(10)
    raise TimeoutError(f"Pipeline did not finish within {timeout}s")


def step_3(client: FabricClient, cfg: dict[str, Any], timeout: int) -> None:
    """Team SPN: connections (3.1) + copy pipeline (3.2) + run pipeline (3.3)."""
    step_3_1(client, cfg)
    step_3_2(client, cfg)
    step_3_3(client, cfg, timeout)


# --- Status (team-scoped: workspace + connections + pipeline) -----------


def step_status(client: FabricClient, cfg: dict[str, Any]) -> None:
    ws = find_workspace(client, cfg["workspace"]["name"], cfg["workspace"].get("id"))
    step_log("status", f"workspace: {'OK ' + ws['id'] if ws else 'MISSING'}")
    if ws:
        gid = cfg["team_workspace_contributor_security_group"]["object_id"]
        assignments = client.get_paged(f"/workspaces/{ws['id']}/roleAssignments")
        has = any(
            a.get("principal", {}).get("id") == gid and a.get("role") == "Contributor" for a in assignments
        )
        step_log("status", f"workspace Contributor for team group: {'OK' if has else 'MISSING'}")
        spn_oid = (cfg.get("workspace") or {}).get("spn_object_id")
        if spn_oid:
            has = any(
                a.get("principal", {}).get("id") == spn_oid and a.get("role") == "Contributor" for a in assignments
            )
            step_log("status", f"workspace Contributor for team SPN: {'OK' if has else 'MISSING'}")
    team_gid = cfg["team_workspace_contributor_security_group"]["object_id"]
    for label, which in (("OPDG", "opdg"), ("VDG", "vdg")):
        try:
            gid_gw = resolve_gateway_id(client, cfg, which, "status")
        except SystemExit as e:
            step_log("status", f"{label}: {e}")
            continue
        try:
            assignments = client.get_paged(f"/gateways/{gid_gw}/roleAssignments")
            has = any(
                a.get("principal", {}).get("id") == team_gid
                and a.get("role") in ("ConnectionCreator", "ConnectionCreatorWithResharing")
                for a in assignments
            )
            step_log("status", f"{label} ConnectionCreator(WithResharing) for team group: {'OK' if has else 'MISSING'}")
        except RuntimeError as e:
            step_log("status", f"{label} role check failed: {e}")
    for which, key in (("source", "source"), ("target", "target")):
        c = find_connection(client, cfg["connections"][key]["name"])
        step_log("status", f"connection {which}: {'OK ' + c['id'] if c else 'MISSING'}")
    if ws:
        p = find_pipeline(client, ws["id"], cfg["pipeline"]["name"])
        step_log("status", f"pipeline: {'OK ' + p['id'] if p else 'MISSING'}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


STEPS = {
    "3":      lambda c, cfg, args: (require_identity(c, "3",   "Integration Team SPN"), step_3(c, cfg, args.timeout)),
    "3.1":    lambda c, cfg, _:    (require_identity(c, "3.1", "Integration Team SPN"), step_3_1(c, cfg)),
    "3.2":    lambda c, cfg, _:    (require_identity(c, "3.2", "Integration Team SPN"), step_3_2(c, cfg)),
    "3.3":    lambda c, cfg, args: (require_identity(c, "3.3", "Integration Team SPN"), step_3_3(c, cfg, args.timeout)),
    "status": lambda c, cfg, _:    step_status(c, cfg),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("step", choices=list(STEPS.keys()), help="Sub-step to run")
    parser.add_argument(
        "config", type=Path,
        help="Path to integration workspace YAML (e.g. config/workspace_team/integration/prod-01.yaml)",
    )
    parser.add_argument(
        "--timeout", type=int, default=900,
        help="Pipeline run polling timeout in seconds (step 3.3)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    client = FabricClient()
    STEPS[args.step](client, cfg, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
