"""
Persona 1: Fabric admin — one-time bootstrap.

Maps to blog section 2.1 "Fabric admin (1) — one-time bootstrap". Runs once per
platform security group and then steps out of the loop.

Steps:
  1.1  Add platform_workspace_security_group to the tenant-setting allow-list for
       "Service principals can create workspaces, connections, and deployment pipelines".
  1.2  Create the Azure resource group (capacity.resource_group) and grant
       platform_workspace_security_group Contributor on it.
  1.3  Grant platform_gateway_security_group Admin on the OPDG (1.3a) and VDG (1.3b).
       Variant-aware: skipped automatically when no gateways are configured (e.g. a
       PBI-only variant that doesn't use OPDG/VDG).

Auth: `az login` as a human Fabric admin, OR `az login --service-principal` as a
bootstrap SPN holding the Entra "Fabric Administrator" directory role plus Owner
(or Contributor + User Access Administrator) on capacity.subscription_id.

Usage:
    python scripts/admin/bootstrap.py 1   config/admin/tenant.yaml   # 1.1 + 1.2 + 1.3
    python scripts/admin/bootstrap.py 1.1 config/admin/tenant.yaml   # single sub-step
    python scripts/admin/bootstrap.py 1.2 config/admin/tenant.yaml
    python scripts/admin/bootstrap.py 1.3 config/admin/tenant.yaml
    python scripts/admin/bootstrap.py tenant-settings config/admin/tenant.yaml
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Any

# Allow `python scripts/admin/bootstrap.py ...` without needing PYTHONPATH set.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _fabric_common import (  # noqa: E402
    AZURE_ROLE_CONTRIBUTOR,
    ArmClient,
    FabricClient,
    assign_gateway_role,
    load_config,
    require_identity,
    step_log,
)


def _require_platform_gateway_group_id(cfg: dict[str, Any], step: str) -> str:
    pgid = (cfg.get("platform_gateway_security_group") or {}).get("object_id")
    if not pgid:
        raise SystemExit(
            f"[{step}] config 'platform_gateway_security_group.object_id' is required for step 1.3"
        )
    return pgid


# ---------------------------------------------------------------------------
# Step 1.1 — tenant allow-list
# ---------------------------------------------------------------------------


def step_1_1(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Add platform_workspace_security_group to the configured tenant-setting allow-lists.

    Mandatory: hard-fails when `tenant_settings.enabled_setting_names` is missing or
    empty. This is what makes the *platform workspace-creator* secgrp actually able
    to create workspaces under "Service principals can create workspaces, connections,
    and deployment pipelines". Idempotent: no-op when the group is already present.

    Requires the Fabric admin running this step to have `Tenant.ReadWrite.All`
    (Fabric tenant-settings update API is in Preview at time of writing).
    """
    ts = cfg.get("tenant_settings") or {}
    names: list[str] = ts.get("enabled_setting_names") or []
    if not names:
        raise SystemExit(
            "[1.1] tenant_settings.enabled_setting_names is required and must list at least "
            "one Fabric tenant setting (e.g. the one gating SPN workspace creation). "
            "Discover names with: python scripts/admin/bootstrap.py tenant-settings <config>"
        )
    pgrp = cfg.get("platform_workspace_security_group") or {}
    graph_id = pgrp.get("object_id")
    if not graph_id:
        raise SystemExit(
            "[1.1] platform_workspace_security_group.object_id is required when "
            "tenant_settings.enabled_setting_names is set"
        )
    display_name = pgrp.get("name")  # optional; Fabric resolves it server-side if omitted
    try:
        settings = client.get_paged("/admin/tenantsettings")
    except RuntimeError as e:
        raise SystemExit(
            f"[1.1] GET /v1/admin/tenantsettings failed: {e}. "
            "Caller must be a Fabric administrator with Tenant.Read.All or Tenant.ReadWrite.All."
        )
    by_name = {s.get("settingName"): s for s in settings}
    for setting_name in names:
        existing = by_name.get(setting_name)
        if existing is None:
            sample = ", ".join(sorted(by_name)[:10])
            raise SystemExit(
                f"[1.1] tenant setting '{setting_name}' not found in this tenant. "
                f"First 10 available: {sample}. Run "
                f"`python scripts/admin/bootstrap.py tenant-settings <config>` to list all."
            )
        groups = list(existing.get("enabledSecurityGroups") or [])
        if any(g.get("graphId") == graph_id for g in groups):
            step_log("1.1", f"'{setting_name}': group already in enabledSecurityGroups (no-op)")
            continue
        new_group: dict[str, Any] = {"graphId": graph_id}
        if display_name:
            new_group["name"] = display_name
        groups.append(new_group)
        body: dict[str, Any] = {
            "enabled": True,
            "enabledSecurityGroups": groups,
        }
        if existing.get("excludedSecurityGroups"):
            body["excludedSecurityGroups"] = existing["excludedSecurityGroups"]
        if existing.get("properties"):
            body["properties"] = existing["properties"]
        for k in ("delegateToCapacity", "delegateToDomain", "delegateToWorkspace"):
            if k in existing:
                body[k] = existing[k]
        client.post(f"/admin/tenantsettings/{setting_name}/update", body)
        step_log(
            "1.1",
            f"'{setting_name}': added '{display_name}' ({graph_id}) to enabledSecurityGroups",
        )


# ---------------------------------------------------------------------------
# Step 1.2 — capacity RG + Contributor for platform_workspace_security_group
# ---------------------------------------------------------------------------


def step_1_2(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Create capacity.resource_group and grant platform_workspace_security_group Contributor.

    Requires the Fabric admin to have, on the subscription named in capacity.subscription_id:
      - `Microsoft.Resources/subscriptions/resourceGroups/write` (RG create) and
      - `Microsoft.Authorization/roleAssignments/write` (role assignment create).
    Sub-scoped Owner satisfies both. Contributor alone is NOT enough.
    """
    cap = cfg.get("capacity") or {}
    for k in ("subscription_id", "resource_group", "location"):
        if not cap.get(k):
            raise SystemExit(f"[1.2] capacity.{k} is required")
    pgrp = cfg.get("platform_workspace_security_group") or {}
    pgid = pgrp.get("object_id")
    if not pgid:
        raise SystemExit("[1.2] platform_workspace_security_group.object_id is required")

    sub = cap["subscription_id"]
    rg = cap["resource_group"]
    location = cap["location"]
    arm = ArmClient()

    # --- 1.2a: idempotent PUT of the resource group ----------------------
    rg_path = f"/subscriptions/{sub}/resourceGroups/{rg}?api-version=2021-04-01"
    rg_resp = arm.request("GET", rg_path)
    if rg_resp.status_code == 403:
        raise SystemExit(
            f"[1.2] GET RG got 403 — caller is missing read access on subscription {sub}. "
            f"Fabric admin running step 1 needs at minimum Reader on the subscription "
            f"(typically Owner or Contributor + User Access Administrator)."
        )
    if rg_resp.status_code == 200:
        step_log("1.2", f"RG '{rg}' already exists in subscription {sub} (location={(rg_resp.json() or {}).get('location')})")
    elif rg_resp.status_code == 404:
        r = arm.request("PUT", rg_path, json={"location": location})
        if r.status_code == 403:
            raise SystemExit(
                f"[1.2] PUT RG got 403 — caller is missing "
                f"Microsoft.Resources/subscriptions/resourceGroups/write on subscription {sub}. "
                f"Grant Contributor (or Owner) at subscription scope."
            )
        if not r.ok:
            raise SystemExit(f"[1.2] PUT RG failed {r.status_code}: {r.text}")
        step_log("1.2", f"Created RG '{rg}' (location={location})")
    else:
        raise SystemExit(f"[1.2] GET RG failed {rg_resp.status_code}: {rg_resp.text}")

    # --- 1.2b: idempotent role assignment (Contributor on the RG) ---------
    rg_scope = f"/subscriptions/{sub}/resourceGroups/{rg}"
    role_def_id = (
        f"/subscriptions/{sub}/providers/Microsoft.Authorization/"
        f"roleDefinitions/{AZURE_ROLE_CONTRIBUTOR}"
    )
    list_path = (
        f"{rg_scope}/providers/Microsoft.Authorization/roleAssignments"
        f"?api-version=2022-04-01&$filter=principalId%20eq%20%27{pgid}%27"
    )
    list_resp = arm.request("GET", list_path)
    if list_resp.status_code == 403:
        raise SystemExit(
            f"[1.2] GET roleAssignments got 403 — caller needs Owner or User Access "
            f"Administrator on RG '{rg}' (or the subscription) to create role assignments."
        )
    if list_resp.status_code != 200:
        raise SystemExit(f"[1.2] GET roleAssignments failed {list_resp.status_code}: {list_resp.text}")
    existing = (list_resp.json() or {}).get("value") or []
    already = any(
        (a.get("properties") or {}).get("roleDefinitionId", "").lower().endswith(AZURE_ROLE_CONTRIBUTOR)
        for a in existing
    )
    if already:
        step_log("1.2", f"platform_workspace_security_group {pgid} already has Contributor on RG '{rg}' (no-op)")
        return
    ra_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{rg_scope}|{pgid}|Contributor"))
    create_path = (
        f"{rg_scope}/providers/Microsoft.Authorization/roleAssignments/"
        f"{ra_guid}?api-version=2022-04-01"
    )
    body = {
        "properties": {
            "roleDefinitionId": role_def_id,
            "principalId": pgid,
            "principalType": "Group",
        }
    }
    r = arm.request("PUT", create_path, json=body)
    if r.status_code == 403:
        raise SystemExit(
            f"[1.2] PUT roleAssignment got 403 — caller needs Owner or User Access "
            f"Administrator on RG '{rg}' (or the subscription). Contributor alone is not enough."
        )
    if r.status_code == 409 and "RoleAssignmentExists" in r.text:
        step_log("1.2", f"Role assignment already exists for group {pgid} on RG '{rg}' (no-op)")
        return
    if r.status_code not in (200, 201):
        raise SystemExit(f"[1.2] PUT roleAssignment failed {r.status_code}: {r.text}")
    step_log("1.2", f"Granted platform_workspace_security_group {pgid} Contributor on RG '{rg}'")


# ---------------------------------------------------------------------------
# Step 1.3 — gateway Admin for platform_gateway_security_group
# ---------------------------------------------------------------------------


def _has_gateway_config(cfg: dict[str, Any]) -> bool:
    """True when the YAML actually references at least one gateway.

    Variant gate: a PBI-only platform variant has no OPDG/VDG, so step 1.3 must
    no-op rather than fail. An integration variant always sets `gateways.opdg`
    and/or `gateways.vdg`.
    """
    gw = cfg.get("gateways") or {}
    return any(gw.get(k) for k in ("opdg", "opdg_id", "vdg", "vdg_id"))


def step_1_3a(client: FabricClient, cfg: dict[str, Any]) -> None:
    assign_gateway_role(
        client, cfg, "opdg", "1.3a",
        principal_id=_require_platform_gateway_group_id(cfg, "1.3a"),
        role="Admin",
    )


def step_1_3b(client: FabricClient, cfg: dict[str, Any]) -> None:
    assign_gateway_role(
        client, cfg, "vdg", "1.3b",
        principal_id=_require_platform_gateway_group_id(cfg, "1.3b"),
        role="Admin",
    )


def step_1_3(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Fabric admin: grant platform_gateway_security_group Admin on OPDG (1.3a) + VDG (1.3b).

    No-op for variants that don't use gateways (no `gateways:` section in YAML).
    """
    if not _has_gateway_config(cfg):
        step_log("1.3", "no gateways configured in YAML — skipping (non-integration variant)")
        return
    step_1_3a(client, cfg)
    step_1_3b(client, cfg)


def step_1(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Fabric admin bootstrap: tenant allow-list (1.1) + RG create + role assign (1.2) + gateway Admin (1.3)."""
    step_1_1(client, cfg)
    step_1_2(client, cfg)
    step_1_3(client, cfg)


# ---------------------------------------------------------------------------
# Diagnostic helper — list all tenant settings
# ---------------------------------------------------------------------------


def step_tenant_settings(client: FabricClient, cfg: dict[str, Any]) -> None:
    """List all Fabric tenant settings so the admin can pick names for tenant_settings.enabled_setting_names.

    Requires Fabric admin + Tenant.Read.All (Preview API).
    """
    settings = client.get_paged("/admin/tenantsettings")
    step_log("tenant-settings", f"{len(settings)} setting(s) returned (sorted by settingName):")
    for s in sorted(settings, key=lambda x: x.get("settingName", "")):
        sn = s.get("settingName", "?")
        enabled = "ON " if s.get("enabled") else "off"
        groups = s.get("enabledSecurityGroups") or []
        if not groups:
            scope = "[entire org]" if s.get("enabled") else "[disabled]"
        else:
            names = ", ".join(g.get("name", "?") for g in groups)
            scope = f"[{len(groups)} group(s): {names}]"
        title = s.get("title", "")
        print(f"  {enabled}  {sn:<55}  {scope:<60}  {title}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


STEPS = {
    "1":   lambda c, cfg: (require_identity(c, "1",   "Fabric admin"), step_1(c, cfg)),
    "1.1": lambda c, cfg: (require_identity(c, "1.1", "Fabric admin"), step_1_1(c, cfg)),
    "1.2": lambda c, cfg: (require_identity(c, "1.2", "Fabric admin"), step_1_2(c, cfg)),
    "1.3": lambda c, cfg: (require_identity(c, "1.3", "Fabric admin"), step_1_3(c, cfg)),
    "tenant-settings": lambda c, cfg: step_tenant_settings(c, cfg),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("step", choices=list(STEPS.keys()), help="Sub-step to run")
    parser.add_argument("config", type=Path, help="Path to admin YAML (e.g. config/admin/tenant.yaml)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    client = FabricClient()
    STEPS[args.step](client, cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
