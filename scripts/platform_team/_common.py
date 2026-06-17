"""
Platform team — variant-independent base steps.

Both `integration.py` and (future) `pbi.py` build on these:

  2.1  ARM-create the Fabric capacity in the RG provisioned by 1.2; self-assign
       capacity Admin so the Platform SPN can bind the workspace in 2.2 without a
       portal step.
  2.2  Create the team workspace bound to the capacity, then grant the team
       security group + (optionally) the team SPN directly Contributor on it.

Variant-specific federation (e.g. integration's OPDG/VDG ConnectionCreator grant)
lives in the variant module, not here.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from _fabric_common import (
    ArmClient,
    FabricClient,
    find_capacity,
    find_workspace,
    require_workspace,
    step_log,
)


# --- Step 2.1: Platform SPN — create the Fabric capacity (ARM) ---------


def step_2_1(client: FabricClient, cfg: dict[str, Any]) -> None:
    cap = cfg.get("capacity") or {}
    for k in ("subscription_id", "resource_group", "name", "location"):
        if not cap.get(k):
            raise SystemExit(
                f"[2.1] capacity.{k} is required (see config/platform/<variant>/<env>.example.yaml)"
            )
    sub = cap["subscription_id"]
    rg = cap["resource_group"]
    name = cap["name"]
    location = cap["location"]
    sku = cap.get("sku") or "F2"

    arm = ArmClient()
    self_oid = arm.whoami_oid()
    path = (
        f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Fabric/capacities/"
        f"{name}?api-version=2023-11-01"
    )
    rg_scope = f"/subscriptions/{sub}/resourceGroups/{rg}"

    def _fail_403(action: str, resp: requests.Response) -> None:
        raise SystemExit(
            f"[2.1] {action} got 403 — the current identity ({self_oid}) is missing\n"
            f"     Microsoft.Fabric/capacities/write (or Contributor) on RG '{rg}'.\n"
            f"     Step 1.2 should have granted platform_workspace_security_group Contributor on\n"
            f"     this RG; verify the Platform SPN is a member of that group. If you skipped\n"
            f"     step 1.2, you can manually grant it with (run as subscription Owner / UAA):\n"
            f"\n"
            f"       az role assignment create \\\n"
            f"         --assignee-object-id {self_oid} --assignee-principal-type ServicePrincipal \\\n"
            f"         --role Contributor \\\n"
            f"         --scope {rg_scope}\n"
            f"\n"
            f"     Full ARM response: {resp.status_code} {resp.text}"
        )

    get_resp = arm.request("GET", path)
    if get_resp.status_code == 403:
        _fail_403("GET capacity", get_resp)
    if get_resp.status_code == 200:
        existing = get_resp.json()
        members = (((existing.get("properties") or {}).get("administration")) or {}).get("members") or []
        step_log("2.1", f"Capacity '{name}' already exists in RG '{rg}' (sku={(existing.get('sku') or {}).get('name', '?')})")
        if self_oid not in members:
            patch_body = {"properties": {"administration": {"members": sorted({*members, self_oid})}}}
            r = arm.request("PATCH", path, json=patch_body)
            if r.status_code == 403:
                _fail_403("PATCH capacity admins", r)
            if not r.ok:
                raise SystemExit(f"[2.1] PATCH capacity admins failed {r.status_code}: {r.text}")
            step_log("2.1", f"Added self ({self_oid}) to capacity administration.members")
        else:
            step_log("2.1", f"Self ({self_oid}) already in capacity administration.members (no-op)")
    elif get_resp.status_code == 404:
        body = {
            "location": location,
            "sku": {"name": sku, "tier": "Fabric"},
            "properties": {"administration": {"members": [self_oid]}},
        }
        r = arm.request("PUT", path, json=body)
        if r.status_code == 403:
            _fail_403("PUT capacity", r)
        if r.status_code not in (200, 201, 202):
            raise SystemExit(f"[2.1] PUT capacity failed {r.status_code}: {r.text}")
        step_log("2.1", f"Submitted capacity create '{name}' (sku={sku}, location={location})")
        deadline = time.time() + 600
        while time.time() < deadline:
            time.sleep(10)
            r2 = arm.request("GET", path)
            if r2.status_code != 200:
                step_log("2.1", f"  GET returned {r2.status_code}; retrying")
                continue
            state = ((r2.json().get("properties") or {}).get("provisioningState"))
            step_log("2.1", f"  provisioningState={state}")
            if state == "Succeeded":
                break
            if state in ("Failed", "Canceled"):
                raise SystemExit(f"[2.1] capacity provisioning ended in state '{state}': {r2.text}")
        else:
            raise SystemExit("[2.1] capacity provisioning did not complete within 600s")
    else:
        raise SystemExit(f"[2.1] GET capacity failed {get_resp.status_code}: {get_resp.text}")

    # Resolve the Fabric capacity GUID (the workspace assign API wants this, not the ARM name).
    capacities = client.get_paged("/capacities")
    match = next((c for c in capacities if c.get("displayName") == name), None)
    if not match:
        raise SystemExit(
            f"[2.1] capacity '{name}' was created/found via ARM but is not yet visible to "
            f"the current identity via Fabric GET /v1/capacities. Wait ~30s and re-run step 2.1."
        )
    cap_id = match["id"]
    cfg["capacity"]["id"] = cap_id
    step_log("2.1", f"Fabric capacity GUID = {cap_id}")


# --- Step 2.2: Platform SPN — workspace lifecycle ----------------------


def step_2_2a(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    name = cfg["workspace"]["name"]
    existing = find_workspace(client, name, cfg["workspace"].get("id"))
    if existing:
        step_log("2.2a", f"Workspace '{name}' already exists (id={existing['id']})")
        cfg["workspace"]["id"] = existing["id"]
        return existing
    # Resolve the Fabric capacity GUID. Prefer an in-memory id set by step 2.1
    # earlier in this same process; otherwise discover by name from Fabric.
    cap_id = (cfg.get("capacity") or {}).get("id")
    if not cap_id:
        cap_name = (cfg.get("capacity") or {}).get("name")
        if not cap_name:
            raise SystemExit("[2.2a] capacity.name is required to look up the Fabric capacity")
        match = find_capacity(client, cap_name)
        if not match:
            raise SystemExit(
                f"[2.2a] capacity '{cap_name}' not visible to the current identity. "
                f"Run step 2.1 first to create it."
            )
        cap_id = match["id"]
        cfg["capacity"]["id"] = cap_id
    body: dict[str, Any] = {"displayName": name, "capacityId": cap_id}
    ws = client.post("/workspaces", body)
    step_log("2.2a", f"Created workspace '{name}' (id={ws['id']})")
    cfg["workspace"]["id"] = ws["id"]
    return ws


def step_2_2b(client: FabricClient, cfg: dict[str, Any]) -> None:
    ws = require_workspace(client, cfg, "2.2b")
    gid = cfg["team_workspace_contributor_security_group"]["object_id"]
    role = "Contributor"
    assignments = client.get_paged(f"/workspaces/{ws['id']}/roleAssignments")
    if any(a.get("principal", {}).get("id") == gid and a.get("role") == role for a in assignments):
        step_log("2.2b", f"Group {gid} already has role '{role}' on workspace")
        return
    client.post(
        f"/workspaces/{ws['id']}/roleAssignments",
        {"principal": {"id": gid, "type": "Group"}, "role": role},
    )
    step_log("2.2b", f"Assigned group {gid} as {role} on workspace '{ws['displayName']}'")


def step_2_2c(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Assign the team SPN directly as Contributor on the workspace.

    Belt-and-braces alongside the group assignment in 2.2b: group membership in Fabric
    can be unreliable (propagation delays, AAD/Fabric sync edge cases), and a direct
    role assignment guarantees the SPN sees the workspace via GET /v1/workspaces/{id}.
    Skipped silently if workspace.spn_object_id is not set in YAML.
    """
    ws_cfg = cfg.get("workspace", {})
    oid = ws_cfg.get("spn_object_id")
    if not oid:
        step_log("2.2c", "workspace.spn_object_id not set; skipping direct SPN assignment")
        return
    ws = require_workspace(client, cfg, "2.2c")
    role = "Contributor"
    assignments = client.get_paged(f"/workspaces/{ws['id']}/roleAssignments")
    if any(a.get("principal", {}).get("id") == oid and a.get("role") == role for a in assignments):
        step_log("2.2c", f"SPN {oid} already has role '{role}' on workspace")
        return
    client.post(
        f"/workspaces/{ws['id']}/roleAssignments",
        {"principal": {"id": oid, "type": "ServicePrincipal"}, "role": role},
    )
    step_log("2.2c", f"Assigned SPN {oid} as {role} on workspace '{ws['displayName']}'")


def step_2_2(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Platform SPN: create workspace and grant team secgrp + team SPN Contributor on it."""
    step_2_2a(client, cfg)
    step_2_2b(client, cfg)  # team secgrp -> workspace Contributor
    step_2_2c(client, cfg)  # team SPN direct Contributor (belt-and-braces, no-op if oid not set)
