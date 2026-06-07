"""
Provision a Microsoft Fabric workspace end-to-end for a customer demo.

Three personas, federated by design, seven steps:

    # --- Step 1: Fabric admin (interactive, one-time bootstrap) ---
    # Grants the *platform gateway-admin* security group Admin on the OPDG and VDG
    # so its members (e.g. the Platform SPN) can later delegate ConnectionCreatorWithResharing
    # to team security groups without involving the Fabric admin again.
    az login
    python scripts/provision_fabric.py 1 config/prod-01.yaml

    # --- Steps 2-4: Platform SPN (member of both platform security groups) ---
    # Step 2: ARM-create a Microsoft.Fabric/capacities F2 capacity in the RG the Platform
    #         SPN has Contributor on, and self-assign capacity Admin (so step 3 can bind
    #         the workspace without any Fabric Admin portal step).
    # Step 3: create the workspace and grant the team security group (+ team SPN)
    #         Contributor on the workspace.
    # Step 4: federate gateway access — grant the team security group
    #         ConnectionCreatorWithResharing on the OPDG and VDG.
    az logout
    az login --service-principal --username <platform-app-id> --tenant <tenant-id> --password <secret>
    python scripts/provision_fabric.py 2 config/prod-01.yaml
    python scripts/provision_fabric.py 3 config/prod-01.yaml
    python scripts/provision_fabric.py 4 config/prod-01.yaml

    # --- Steps 5-7: Team SPN (member of the team security group) ---
    az logout
    az login --service-principal --username <team-app-id> --tenant <tenant-id> --password <secret>

    python scripts/provision_fabric.py 5 config/prod-01.yaml   # SQL source + ADLS target connections
    python scripts/provision_fabric.py 6 config/prod-01.yaml   # create/update the copy pipeline
    python scripts/provision_fabric.py 7 config/prod-01.yaml   # run the pipeline (polls)

Convenience:
    python scripts/provision_fabric.py all             config/prod-01.yaml  # run 1 -> 7 (single identity)
    python scripts/provision_fabric.py status          config/prod-01.yaml  # show current state
    python scripts/provision_fabric.py tenant-settings config/prod-01.yaml  # list tenant settings (Fabric admin)

Every step is idempotent: re-running checks for the existing object first.
Step 5 also auto-retries POST /connections on transient upstream errors
(e.g. Azure SQL serverless DB resuming, gateway DataSourceAccessError) with
exponential backoff before bailing out.

Assumptions: SQL source (e.g. Azure SQL / AdventureWorksLT), target ADLS Gen2, OPDG,
virtual DG, *two* platform security groups (workspace-creator + gateway-admin) and a
team security group, platform + team SPNs, and a Key Vault holding the SQL password
and team SPN secret already exist. The Platform SPN must have Contributor (or
`Microsoft.Fabric/capacities/write`) on the Azure RG named in `capacity.resource_group`
so step 2 can create the Fabric capacity. The "Service principals can create workspaces"
tenant allow-list is managed by step 1.3 via the Fabric tenant-settings Preview REST API
(mandatory, configured in YAML).
Auth: `az login` (DefaultAzureCredential).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any

import os

import requests
import yaml
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FABRIC_BASE = "https://api.fabric.microsoft.com/v1"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
ARM_BASE = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"


# ---------------------------------------------------------------------------
# Low-level HTTP helpers
# ---------------------------------------------------------------------------


class FabricClient:
    def __init__(self) -> None:
        self._cred = DefaultAzureCredential()
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() > self._token_expires_at - 300:
            tok = self._cred.get_token(FABRIC_SCOPE)
            self._token = tok.token
            self._token_expires_at = tok.expires_on
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = path if path.startswith("http") else f"{FABRIC_BASE}{path}"
        resp = requests.request(method, url, headers=self._headers(), timeout=60, **kwargs)
        if not resp.ok:
            raise RuntimeError(f"{method} {url} -> {resp.status_code}: {resp.text}")
        return resp

    def get(self, path: str) -> Any:
        return self.request("GET", path).json()

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        resp = self.request("POST", path, json=body or {})
        if resp.status_code == 202:
            return {"_location": resp.headers.get("Location"), "_status": 202}
        if resp.content:
            try:
                return resp.json()
            except ValueError:
                return {}
        return {}

    def get_paged(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        url: str | None = path
        while url:
            data = self.get(url)
            items.extend(data.get("value", []))
            url = data.get("continuationUri")
        return items

    def whoami(self) -> str:
        """Return a short label for the identity in the current Fabric token (oid/appid/upn)."""
        self._headers()  # ensure token is fetched
        assert self._token is not None
        try:
            payload_b64 = self._token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:  # pragma: no cover - best-effort decoding
            return "<unknown identity>"
        return (
            claims.get("upn")
            or claims.get("unique_name")
            or claims.get("app_displayname")
            or f"appid={claims.get('appid', '?')} oid={claims.get('oid', '?')}"
        )


class ArmClient:
    """Thin Azure Resource Manager client. Same auth pattern as FabricClient but ARM scope."""

    def __init__(self) -> None:
        self._cred = DefaultAzureCredential()
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() > self._token_expires_at - 300:
            tok = self._cred.get_token(ARM_SCOPE)
            self._token = tok.token
            self._token_expires_at = tok.expires_on
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = path if path.startswith("http") else f"{ARM_BASE}{path}"
        return requests.request(method, url, headers=self._headers(), timeout=120, **kwargs)

    def whoami_oid(self) -> str:
        """Return the object id of the currently authenticated principal (from JWT 'oid' claim)."""
        self._headers()  # ensure token
        assert self._token is not None
        try:
            payload_b64 = self._token.split(".")[1]
            payload_b64 += "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:  # pragma: no cover
            raise SystemExit(f"Failed to decode ARM token claims: {e}")
        oid = claims.get("oid")
        if not oid:
            raise SystemExit("ARM token has no 'oid' claim; cannot self-assign capacity admin")
        return oid


def step_log(step: str, msg: str) -> None:
    print(f"[{step}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Sidecar state file: persists ids discovered by step 2 (capacity GUID) and
# step 3 (workspace id) so that later steps running as the Team SPN do not
# depend on `GET /v1/workspaces` or `GET /v1/capacities`, which are unreliable
# for SPNs that only have access via a security group. The state file lives
# next to the YAML as `<cfg>.state.yaml` and is git-ignored.
# ---------------------------------------------------------------------------


def _state_path(cfg_path: Path) -> Path:
    return cfg_path.with_suffix(".state.yaml")


def _load_state_into_cfg(cfg: dict[str, Any], cfg_path: Path) -> None:
    sp = _state_path(cfg_path)
    if not sp.exists():
        return
    state = yaml.safe_load(sp.read_text()) or {}
    ws_id = (state.get("workspace") or {}).get("id")
    if ws_id and not cfg.get("workspace", {}).get("id"):
        cfg.setdefault("workspace", {})["id"] = ws_id
        step_log("init", f"loaded workspace.id={ws_id} from {sp.name}")
    cap_id = (state.get("capacity") or {}).get("id")
    if cap_id and not cfg.get("capacity", {}).get("id"):
        cfg.setdefault("capacity", {})["id"] = cap_id
        step_log("init", f"loaded capacity.id={cap_id} from {sp.name}")


def _save_workspace_id(cfg: dict[str, Any], workspace_id: str) -> None:
    cfg_path = cfg.get("_cfg_path")
    if not cfg_path:
        return
    sp = _state_path(cfg_path)
    state = yaml.safe_load(sp.read_text()) if sp.exists() else {}
    state = state or {}
    state.setdefault("workspace", {})["id"] = workspace_id
    sp.write_text(yaml.safe_dump(state, sort_keys=False))
    step_log("3.1", f"persisted workspace.id={workspace_id} to {sp.name}")


def _save_capacity_id(cfg: dict[str, Any], capacity_id: str) -> None:
    cfg_path = cfg.get("_cfg_path")
    if not cfg_path:
        return
    sp = _state_path(cfg_path)
    state = yaml.safe_load(sp.read_text()) if sp.exists() else {}
    state = state or {}
    state.setdefault("capacity", {})["id"] = capacity_id
    sp.write_text(yaml.safe_dump(state, sort_keys=False))
    step_log("2", f"persisted capacity.id={capacity_id} to {sp.name}")


def require_identity(client: FabricClient, step: str, role: str) -> None:
    """Print the active Fabric identity so the operator can confirm the right login is in use."""
    step_log(step, f"acting as {role}: {client.whoami()}")


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def find_workspace(client: FabricClient, name: str, workspace_id: str | None = None) -> dict[str, Any] | None:
    # Prefer direct GET when an id is configured: SPNs without the tenant setting
    # "Service principals can use Fabric APIs" get an empty list from GET /v1/workspaces,
    # even when they are Contributor on the workspace. GET /v1/workspaces/{id} still works.
    if workspace_id:
        try:
            return client.get(f"/workspaces/{workspace_id}")
        except RuntimeError as e:
            step_log("lookup", f"WARN GET /workspaces/{workspace_id} failed: {e}")
            step_log("lookup", "falling back to list-and-filter")
    return next((w for w in client.get_paged("/workspaces") if w["displayName"] == name), None)


def find_connection(client: FabricClient, name: str) -> dict[str, Any] | None:
    return next((c for c in client.get_paged("/connections") if c.get("displayName") == name), None)


def find_pipeline(client: FabricClient, workspace_id: str, name: str) -> dict[str, Any] | None:
    return next(
        (
            i
            for i in client.get_paged(f"/workspaces/{workspace_id}/items")
            if i.get("displayName") == name and i.get("type") == "DataPipeline"
        ),
        None,
    )


def require_workspace(client: FabricClient, cfg: dict[str, Any], step: str) -> dict[str, Any]:
    ws = find_workspace(client, cfg["workspace"]["name"], cfg["workspace"].get("id"))
    if not ws:
        raise SystemExit(f"[{step}] Workspace '{cfg['workspace']['name']}' not found. Run step 3.1 first.")
    return ws


def require_connection(client: FabricClient, name: str, step: str) -> dict[str, Any]:
    conn = find_connection(client, name)
    if not conn:
        raise SystemExit(f"[{step}] Connection '{name}' not found. Run the matching step 5 first.")
    return conn


# Cache of gateway display-name -> id so we only call /v1/gateways once per run.
_GATEWAY_CACHE: dict[str, str] | None = None


def _gateway_name_to_id(client: FabricClient, name: str, step: str) -> str:
    global _GATEWAY_CACHE
    if _GATEWAY_CACHE is None:
        _GATEWAY_CACHE = {g["displayName"]: g["id"] for g in client.get_paged("/gateways") if g.get("displayName")}
    if name not in _GATEWAY_CACHE:
        known = ", ".join(sorted(_GATEWAY_CACHE)) or "<none visible to this identity>"
        raise SystemExit(
            f"[{step}] Gateway '{name}' not found. Visible to current identity: {known}"
        )
    return _GATEWAY_CACHE[name]


def resolve_gateway_id(client: FabricClient, cfg: dict[str, Any], which: str, step: str) -> str:
    """Resolve a gateway id from config. Accepts either '<which>_id' (literal GUID) or '<which>' (display name).

    which is 'opdg' or 'vdg'.
    """
    gateways = cfg.get("gateways", {})
    if gateways.get(f"{which}_id"):
        return gateways[f"{which}_id"]
    if gateways.get(which):
        return _gateway_name_to_id(client, gateways[which], step)
    raise SystemExit(
        f"[{step}] config 'gateways' must define either '{which}' (name) or '{which}_id' (GUID)"
    )


# ---------------------------------------------------------------------------
# Step implementations (each is idempotent)
# ---------------------------------------------------------------------------


def _assign_gateway_role(
    client: FabricClient, cfg: dict[str, Any], which: str, step: str,
    *,
    principal_id: str,
    principal_type: str = "Group",
    role: str = "ConnectionCreator",
) -> None:
    """Idempotently assign a principal a role on the OPDG (which='opdg') or VDG (which='vdg').

    - If the principal already has the requested role, no-op.
    - If the principal has a *different* role, PATCH the assignment to the new role.
    - Otherwise POST a new assignment.
    """
    gid_gw = resolve_gateway_id(client, cfg, which, step)
    assignments = client.get_paged(f"/gateways/{gid_gw}/roleAssignments")
    existing = next(
        (a for a in assignments if a.get("principal", {}).get("id") == principal_id),
        None,
    )
    if existing is not None:
        if existing.get("role") == role:
            step_log(step, f"{principal_type} {principal_id} already has role '{role}' on gateway {gid_gw}")
            return
        ra_id = existing.get("id") or principal_id  # role-assignment id == principal id in Fabric
        client.request(
            "PATCH",
            f"/gateways/{gid_gw}/roleAssignments/{ra_id}",
            json={"role": role},
        )
        step_log(
            step,
            f"Updated {principal_type} {principal_id} on gateway {gid_gw}: "
            f"'{existing.get('role')}' -> '{role}'",
        )
        return
    client.post(
        f"/gateways/{gid_gw}/roleAssignments",
        {"principal": {"id": principal_id, "type": principal_type}, "role": role},
    )
    step_log(step, f"Assigned {principal_type} {principal_id} as {role} on gateway {gid_gw}")


def _require_platform_gateway_group_id(cfg: dict[str, Any], step: str) -> str:
    pgid = (cfg.get("platform_gateway_security_group") or {}).get("object_id")
    if not pgid:
        raise SystemExit(
            f"[{step}] config 'platform_gateway_security_group.object_id' is required for step 1"
        )
    return pgid


# --- Step 1: Fabric admin (one-time bootstrap) -----------------------------
# Grants the platform *gateway-admin* security group Admin on the OPDG and VDG so its
# members (the Platform SPN) can later assign ConnectionCreatorWithResharing to team
# groups without involving the Fabric admin again. Note: the docs say
# ConnectionCreatorWithResharing is sufficient to call POST /v1/gateways/{id}/roleAssignments,
# but in practice that returns 403 InsufficientPermissionsToManageGateway — only Admin
# works. Step 1.3 also adds the platform *workspace-creator* group to the tenant-setting
# allow-lists named in YAML.
#
# Capacity Contributors is no longer a manual prereq: step 2 (Platform SPN) creates a
# Microsoft.Fabric/capacities resource via ARM and self-assigns capacity Admin, which
# is a superset of Contributor and unlocks workspace-to-capacity binding.


def step_1_1(client: FabricClient, cfg: dict[str, Any]) -> None:
    _assign_gateway_role(
        client, cfg, "opdg", "1.1",
        principal_id=_require_platform_gateway_group_id(cfg, "1.1"),
        role="Admin",
    )


def step_1_2(client: FabricClient, cfg: dict[str, Any]) -> None:
    _assign_gateway_role(
        client, cfg, "vdg", "1.2",
        principal_id=_require_platform_gateway_group_id(cfg, "1.2"),
        role="Admin",
    )


def step_1_3(client: FabricClient, cfg: dict[str, Any]) -> None:
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
            "[1.3] tenant_settings.enabled_setting_names is required and must list at least "
            "one Fabric tenant setting (e.g. the one gating SPN workspace creation). "
            "Discover names with: python scripts/provision_fabric.py tenant-settings <config>"
        )
    pgrp = cfg.get("platform_workspace_security_group") or {}
    graph_id = pgrp.get("object_id")
    if not graph_id:
        raise SystemExit(
            "[1.3] platform_workspace_security_group.object_id is required when "
            "tenant_settings.enabled_setting_names is set"
        )
    display_name = pgrp.get("name")  # optional; Fabric resolves it server-side if omitted
    try:
        settings = client.get_paged("/admin/tenantsettings")
    except RuntimeError as e:
        raise SystemExit(
            f"[1.3] GET /v1/admin/tenantsettings failed: {e}. "
            "Caller must be a Fabric administrator with Tenant.Read.All or Tenant.ReadWrite.All."
        )
    by_name = {s.get("settingName"): s for s in settings}
    for setting_name in names:
        existing = by_name.get(setting_name)
        if existing is None:
            sample = ", ".join(sorted(by_name)[:10])
            raise SystemExit(
                f"[1.3] tenant setting '{setting_name}' not found in this tenant. "
                f"First 10 available: {sample}. Run "
                f"`python scripts/provision_fabric.py tenant-settings <config>` to list all."
            )
        groups = list(existing.get("enabledSecurityGroups") or [])
        if any(g.get("graphId") == graph_id for g in groups):
            step_log("1.3", f"'{setting_name}': group already in enabledSecurityGroups (no-op)")
            continue
        new_group: dict[str, Any] = {"graphId": graph_id}
        if display_name:
            new_group["name"] = display_name
        groups.append(new_group)
        body: dict[str, Any] = {
            "enabled": True,
            "enabledSecurityGroups": groups,
        }
        # Preserve other fields so this update doesn't inadvertently clear them.
        if existing.get("excludedSecurityGroups"):
            body["excludedSecurityGroups"] = existing["excludedSecurityGroups"]
        if existing.get("properties"):
            body["properties"] = existing["properties"]
        for k in ("delegateToCapacity", "delegateToDomain", "delegateToWorkspace"):
            if k in existing:
                body[k] = existing[k]
        client.post(f"/admin/tenantsettings/{setting_name}/update", body)
        step_log(
            "1.3",
            f"'{setting_name}': added '{display_name}' ({graph_id}) to enabledSecurityGroups",
        )


# --- Step 2: Platform SPN — create the Fabric capacity (ARM) -------------
# Idempotent PUT of Microsoft.Fabric/capacities/{name}. The Platform SPN
# self-assigns capacity Admin via properties.administration.members, which is a
# superset of "Contributor" and unlocks workspace-to-capacity binding in step 3
# without any manual Fabric Admin portal step. Requires the Platform SPN to have
# `Microsoft.Fabric/capacities/write` (e.g. Contributor) on the target RG.
#
# Persists the discovered Fabric capacity GUID to <cfg>.state.yaml so step 3 can
# reuse it (and so re-runs don't depend on Fabric returning the capacity in
# GET /v1/capacities before the YAML is updated).


def step_2(client: FabricClient, cfg: dict[str, Any]) -> None:
    cap = cfg.get("capacity") or {}
    for k in ("subscription_id", "resource_group", "name", "location"):
        if not cap.get(k):
            raise SystemExit(
                f"[2] capacity.{k} is required (see config/<env>.example.yaml for the schema)"
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
            f"[2] {action} got 403 \u2014 the current identity ({self_oid}) is missing\n"
            f"     Microsoft.Fabric/capacities/write (or Contributor) on RG '{rg}'.\n"
            f"     Grant it once with (run as a subscription Owner / User Access Administrator):\n"
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
        step_log("2", f"Capacity '{name}' already exists in RG '{rg}' (sku={(existing.get('sku') or {}).get('name', '?')})")
        if self_oid not in members:
            patch_body = {"properties": {"administration": {"members": sorted({*members, self_oid})}}}
            r = arm.request("PATCH", path, json=patch_body)
            if r.status_code == 403:
                _fail_403("PATCH capacity admins", r)
            if not r.ok:
                raise SystemExit(f"[2] PATCH capacity admins failed {r.status_code}: {r.text}")
            step_log("2", f"Added self ({self_oid}) to capacity administration.members")
        else:
            step_log("2", f"Self ({self_oid}) already in capacity administration.members (no-op)")
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
            raise SystemExit(f"[2] PUT capacity failed {r.status_code}: {r.text}")
        step_log("2", f"Submitted capacity create '{name}' (sku={sku}, location={location})")
        deadline = time.time() + 600
        while time.time() < deadline:
            time.sleep(10)
            r2 = arm.request("GET", path)
            if r2.status_code != 200:
                step_log("2", f"  GET returned {r2.status_code}; retrying")
                continue
            state = ((r2.json().get("properties") or {}).get("provisioningState"))
            step_log("2", f"  provisioningState={state}")
            if state == "Succeeded":
                break
            if state in ("Failed", "Canceled"):
                raise SystemExit(f"[2] capacity provisioning ended in state '{state}': {r2.text}")
        else:
            raise SystemExit("[2] capacity provisioning did not complete within 600s")
    else:
        raise SystemExit(f"[2] GET capacity failed {get_resp.status_code}: {get_resp.text}")

    # Resolve the Fabric capacity GUID (the workspace assign API wants this, not the ARM name).
    capacities = client.get_paged("/capacities")
    match = next((c for c in capacities if c.get("displayName") == name), None)
    if not match:
        raise SystemExit(
            f"[2] capacity '{name}' was created/found via ARM but is not yet visible to "
            f"the current identity via Fabric GET /v1/capacities. Wait ~30s and re-run step 2."
        )
    cap_id = match["id"]
    cfg["capacity"]["id"] = cap_id
    _save_capacity_id(cfg, cap_id)
    step_log("2", f"Fabric capacity GUID = {cap_id}")


# --- Step 3: Platform SPN — workspace lifecycle --------------------------
# Creates the workspace (bound to the capacity created in step 2) and grants the
# team security group + team SPN Contributor on the workspace.


def step_3_1(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    name = cfg["workspace"]["name"]
    existing = find_workspace(client, name, cfg["workspace"].get("id"))
    if existing:
        step_log("3.1", f"Workspace '{name}' already exists (id={existing['id']})")
        cfg["workspace"]["id"] = existing["id"]
        _save_workspace_id(cfg, existing["id"])
        return existing
    cap_id = (cfg.get("capacity") or {}).get("id")
    if not cap_id:
        raise SystemExit(
            "[3.1] capacity.id missing in config + state file. Run step 2 first to create the "
            "Fabric capacity (it persists the GUID to <cfg>.state.yaml)."
        )
    body: dict[str, Any] = {"displayName": name, "capacityId": cap_id}
    ws = client.post("/workspaces", body)
    step_log("3.1", f"Created workspace '{name}' (id={ws['id']})")
    cfg["workspace"]["id"] = ws["id"]
    _save_workspace_id(cfg, ws["id"])
    return ws


def step_3_2(client: FabricClient, cfg: dict[str, Any]) -> None:
    ws = require_workspace(client, cfg, "3.2")
    gid = cfg["security_group"]["object_id"]
    role = "Contributor"
    assignments = client.get_paged(f"/workspaces/{ws['id']}/roleAssignments")
    if any(a.get("principal", {}).get("id") == gid and a.get("role") == role for a in assignments):
        step_log("3.2", f"Group {gid} already has role '{role}' on workspace")
        return
    client.post(
        f"/workspaces/{ws['id']}/roleAssignments",
        {"principal": {"id": gid, "type": "Group"}, "role": role},
    )
    step_log("3.2", f"Assigned group {gid} as {role} on workspace '{ws['displayName']}'")


def step_3_3(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Assign the team SPN directly as Contributor on the workspace.

    Belt-and-braces alongside the group assignment in 3.2: group membership in Fabric
    can be unreliable (propagation delays, AAD/Fabric sync edge cases), and a direct
    role assignment guarantees the SPN sees the workspace via GET /v1/workspaces/{id}.
    Skipped silently if workspace.spn_object_id is not set in YAML.
    """
    ws_cfg = cfg.get("workspace", {})
    oid = ws_cfg.get("spn_object_id")
    if not oid:
        step_log("3.3", "workspace.spn_object_id not set; skipping direct SPN assignment")
        return
    ws = require_workspace(client, cfg, "3.3")
    role = "Contributor"
    assignments = client.get_paged(f"/workspaces/{ws['id']}/roleAssignments")
    if any(a.get("principal", {}).get("id") == oid and a.get("role") == role for a in assignments):
        step_log("3.3", f"SPN {oid} already has role '{role}' on workspace")
        return
    client.post(
        f"/workspaces/{ws['id']}/roleAssignments",
        {"principal": {"id": oid, "type": "ServicePrincipal"}, "role": role},
    )
    step_log("3.3", f"Assigned SPN {oid} as {role} on workspace '{ws['displayName']}'")


# --- Step 4: Platform SPN — gateway federation --------------------------
# Grants the team security group ConnectionCreatorWithResharing on the OPDG and VDG
# so the Team SPN can create connections in step 5 *and* reshare them with other
# principals. The platform gateway-admin secgrp (Admin role from step 1) is allowed
# to assign any role, including ConnectionCreatorWithResharing.


def step_4_1(client: FabricClient, cfg: dict[str, Any]) -> None:
    _assign_gateway_role(
        client, cfg, "opdg", "4.1",
        principal_id=cfg["security_group"]["object_id"],
        role="ConnectionCreatorWithResharing",
    )


def step_4_2(client: FabricClient, cfg: dict[str, Any]) -> None:
    _assign_gateway_role(
        client, cfg, "vdg", "4.2",
        principal_id=cfg["security_group"]["object_id"],
        role="ConnectionCreatorWithResharing",
    )


def _kv_get_secret(vault_url: str, secret_name: str) -> str:
    """Fetch a secret from Azure Key Vault using the same DefaultAzureCredential as the rest of the script."""
    cred = DefaultAzureCredential()
    return SecretClient(vault_url=vault_url, credential=cred).get_secret(secret_name).value


# ---------------------------------------------------------------------------
# On-premises gateway credential encryption
# Port of Microsoft sample (MIT, microsoft/PowerBI-Developer-Samples,
# Python/Encrypt credentials/Encryption sample). The on-premises gateway
# accepts credentials only as an opaque blob built as follows:
#   - Plaintext: {'credentialData':[{'name':'username','value':...},
#                                   {'name':'password','value':...}]}
#   - For 128-byte (1024-bit) modulus: split into 60-byte segments and RSA-OAEP-SHA256
#     encrypt each segment with the gateway public key; concatenate; base64.
#   - For larger modulus: generate random AES-256 key + 64-byte HMAC key, AES-CBC-PKCS7
#     encrypt the plaintext, HMAC-SHA256 over (algId || iv || ciphertext), and RSA-OAEP-SHA256
#     encrypt (lengthPrefix(0x00, 0x01) || aesKey || hmacKey); output is
#     base64(rsaBlob) + base64(algId || mac || iv || ciphertext).
# ---------------------------------------------------------------------------

_OPDG_MODULUS_1024_BYTES = 128
_OPDG_SEGMENT_LENGTH = 60
_OPDG_AES_KEY_BYTES = 32
_OPDG_HMAC_KEY_BYTES = 64
_OPDG_ALG_IDS = bytes([0, 0])  # Aes256CbcPkcs7 + HMACSHA256


def _opdg_serialize_basic(username: str, password: str) -> bytes:
    u = username.encode("unicode_escape").decode()
    p = password.encode("unicode_escape").decode()
    s = (
        "{'credentialData':[{'name':'username','value':'" + u + "'},"
        "{'name':'password','value':'" + p + "'}]}"
    )
    return s.encode("utf-8")


def _opdg_rsa_public_key(modulus_b64: str, exponent_b64: str) -> rsa.RSAPublicKey:
    modulus = int.from_bytes(base64.b64decode(modulus_b64), "big")
    exponent = int.from_bytes(base64.b64decode(exponent_b64), "big")
    return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())


def _opdg_encrypt_1024(plain: bytes, pub: rsa.RSAPublicKey) -> str:
    out = bytearray()
    for i in range(0, len(plain), _OPDG_SEGMENT_LENGTH):
        seg = plain[i:i + _OPDG_SEGMENT_LENGTH]
        out += pub.encrypt(
            seg,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    return base64.b64encode(bytes(out)).decode()


def _opdg_encrypt_higher(plain: bytes, pub: rsa.RSAPublicKey) -> str:
    key_enc = os.urandom(_OPDG_AES_KEY_BYTES)
    key_mac = os.urandom(_OPDG_HMAC_KEY_BYTES)
    iv = os.urandom(16)

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key_enc), modes.CBC(iv), backend=default_backend()).encryptor()
    cipher_text = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())
    h.update(_OPDG_ALG_IDS + iv + cipher_text)
    mac = h.finalize()

    # Key length prefix: 0x00 = 32-byte AES key, 0x01 = 64-byte HMAC key
    keys_blob = bytes([0, 1]) + key_enc + key_mac
    rsa_blob = pub.encrypt(
        keys_blob,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    sym_output = _OPDG_ALG_IDS + mac + iv + cipher_text
    return base64.b64encode(rsa_blob).decode() + base64.b64encode(sym_output).decode()


def _opdg_encrypt_credentials(public_key: dict[str, str], username: str, password: str) -> str:
    modulus_b64 = public_key.get("modulus")
    exponent_b64 = public_key.get("exponent")
    if not modulus_b64 or not exponent_b64:
        raise SystemExit("Gateway publicKey missing modulus/exponent")
    pub = _opdg_rsa_public_key(modulus_b64, exponent_b64)
    plain = _opdg_serialize_basic(username, password)
    if len(base64.b64decode(modulus_b64)) == _OPDG_MODULUS_1024_BYTES:
        return _opdg_encrypt_1024(plain, pub)
    return _opdg_encrypt_higher(plain, pub)


def _build_credentials(
    cfg: dict[str, Any],
    conn_cfg: dict[str, Any],
    step: str,
    *,
    connectivity_type: str,
    gateway_id: str | None,
    gateway_public_key: dict[str, str] | None,
) -> dict[str, Any]:
    """Build the Fabric `credentialDetails.credentials` object for a connection from YAML config."""
    cred_cfg = conn_cfg.get("credential") or {"type": "WorkspaceIdentity"}
    ctype = cred_cfg["type"]
    if ctype == "WorkspaceIdentity":
        return {"credentialType": "WorkspaceIdentity"}
    if ctype == "Basic":
        kv = cfg.get("key_vault") or {}
        if not cred_cfg.get("username"):
            raise SystemExit(f"[{step}] credential.username required for Basic")
        if not kv.get("vault_url") or not kv.get("sql_password_secret_name"):
            raise SystemExit(f"[{step}] key_vault.vault_url and key_vault.sql_password_secret_name required")
        password = _kv_get_secret(kv["vault_url"], kv["sql_password_secret_name"])
        if connectivity_type == "OnPremisesGateway":
            if not gateway_id or not gateway_public_key:
                raise SystemExit(f"[{step}] OPDG Basic credentials require gateway_id and publicKey")
            encrypted = _opdg_encrypt_credentials(gateway_public_key, cred_cfg["username"], password)
            return {
                "credentialType": "Basic",
                "values": [
                    {"gatewayId": gateway_id, "encryptedCredentials": encrypted},
                ],
            }
        # ShareableCloud / VirtualNetworkGateway: send plaintext, Fabric encrypts in transit.
        return {
            "credentialType": "Basic",
            "username": cred_cfg["username"],
            "password": password,
        }
    if ctype == "Key":
        return {"credentialType": "Key", "key": cred_cfg["value"]}
    if ctype == "ServicePrincipal":
        tenant_id = cred_cfg.get("tenant_id")
        client_id = cred_cfg.get("client_id")
        secret_name = cred_cfg.get("secret_name")
        kv = cfg.get("key_vault") or {}
        if not tenant_id or not client_id or not secret_name:
            raise SystemExit(f"[{step}] credential.tenant_id, client_id and secret_name required for ServicePrincipal")
        if not kv.get("vault_url"):
            raise SystemExit(f"[{step}] key_vault.vault_url required to fetch SP secret")
        if connectivity_type == "OnPremisesGateway":
            raise SystemExit(f"[{step}] ServicePrincipal credentials on OPDG are not implemented; use ShareableCloud")
        secret = _kv_get_secret(kv["vault_url"], secret_name)
        return {
            "credentialType": "ServicePrincipal",
            "tenantId": tenant_id,
            "servicePrincipalClientId": client_id,
            "servicePrincipalSecret": secret,
        }
    raise SystemExit(f"[{step}] Unsupported credential.type '{ctype}'")


def _connection_details(conn_cfg: dict[str, Any], step: str) -> dict[str, Any]:
    """Build the connectionDetails block based on what's in conn_cfg (SQL vs ADLS)."""
    if conn_cfg.get("server") and conn_cfg.get("database"):
        return {
            "type": "SQL",
            "creationMethod": "Sql",
            "parameters": [
                {"name": "server", "dataType": "Text", "value": conn_cfg["server"]},
                {"name": "database", "dataType": "Text", "value": conn_cfg["database"]},
            ],
        }
    if conn_cfg.get("adls_account"):
        return {
            "type": "AzureDataLakeStorage",
            "creationMethod": "AzureDataLakeStorage",
            "parameters": [
                {"name": "server", "dataType": "Text",
                 "value": f"https://{conn_cfg['adls_account']}.dfs.core.windows.net"},
                {"name": "path", "dataType": "Text", "value": conn_cfg["container"]},
            ],
        }
    raise SystemExit(f"[{step}] connection '{conn_cfg.get('name')}' has no recognized target (server/database or adls_account)")


def _create_connection(
    client: FabricClient, cfg: dict[str, Any], conn_cfg: dict[str, Any],
    gateway_id: str | None, connectivity_type: str, step: str,
    *, allow_connection_usage_in_gateway: bool = False,
) -> dict[str, Any]:
    name = conn_cfg["name"]
    existing = find_connection(client, name)
    if existing:
        step_log(step, f"Connection '{name}' already exists (id={existing['id']})")
        _assign_connection_group_owner(client, cfg, existing["id"], step)
        return existing
    gateway_public_key: dict[str, str] | None = None
    if connectivity_type == "OnPremisesGateway":
        if not gateway_id:
            raise SystemExit(f"[{step}] OnPremisesGateway connection requires gateway_id")
        gw = client.get(f"/gateways/{gateway_id}")
        gateway_public_key = gw.get("publicKey")
        if not gateway_public_key:
            raise SystemExit(f"[{step}] gateway {gateway_id} did not return a publicKey")
    credentials = _build_credentials(
        cfg, conn_cfg, step,
        connectivity_type=connectivity_type,
        gateway_id=gateway_id,
        gateway_public_key=gateway_public_key,
    )
    # ADLS only supports NotEncrypted for connection-test encryption; SQL supports Encrypted.
    conn_details = _connection_details(conn_cfg, step)
    encryption = "NotEncrypted" if conn_details.get("type") == "AzureDataLakeStorage" else "Encrypted"
    body: dict[str, Any] = {
        "displayName": name,
        "connectivityType": connectivity_type,
        "connectionDetails": conn_details,
        "privacyLevel": "Organizational",
        "credentialDetails": {
            "singleSignOnType": "None",
            "connectionEncryption": encryption,
            "skipTestConnection": False,
            "credentials": credentials,
        },
    }
    if connectivity_type in ("OnPremisesGateway", "VirtualNetworkGateway"):
        body["gatewayId"] = gateway_id
    if connectivity_type == "ShareableCloud" and allow_connection_usage_in_gateway:
        body["allowConnectionUsageInGateway"] = True
    conn = _post_connection_with_retry(client, name, body, step)
    step_log(step, f"Created connection '{name}' (type={connectivity_type}, credential={credentials['credentialType']}, id={conn.get('id')})")
    _assign_connection_group_owner(client, cfg, conn["id"], step)
    return conn


# Transient signatures returned by Fabric when the upstream data source is
# momentarily unavailable. Re-running the script always succeeds, so we retry
# in-process instead of bailing. Examples:
#  - Azure SQL 40613 (paused serverless DB resuming, transient failover)
#  - Generic OPDG "DataSourceAccessError" wrapping a connect timeout
# Fabric returns `isRetriable: false` on these even though they are; we treat
# the inner error code as the source of truth.
_CONNECTION_RETRY_SIGNATURES = (
    "DM_GWPipeline_Gateway_DataSourceAccessError",
    "is not currently available",
    "40613",
    "CreateGatewayConnectionFailed",
)


def _post_connection_with_retry(
    client: FabricClient, name: str, body: dict[str, Any], step: str,
    *, attempts: int = 4, backoff_s: tuple[int, ...] = (10, 30, 60),
) -> dict[str, Any]:
    """POST /connections with retry on transient upstream-data-source errors.

    Between attempts, re-checks GET /connections in case Fabric created the
    connection server-side despite returning a 4xx.
    """
    last_err: Exception | None = None
    for attempt in range(1, attempts + 1):
        # Defensive: if a prior attempt actually created the connection, pick it up.
        if attempt > 1:
            existing = find_connection(client, name)
            if existing:
                step_log(step, f"  retry detected connection '{name}' exists (id={existing['id']}); using it")
                return existing
        try:
            return client.post("/connections", body)
        except RuntimeError as e:
            msg = str(e)
            is_transient = any(sig in msg for sig in _CONNECTION_RETRY_SIGNATURES)
            if not is_transient or attempt == attempts:
                raise
            delay = backoff_s[min(attempt - 1, len(backoff_s) - 1)]
            step_log(step, f"  transient error on POST /connections (attempt {attempt}/{attempts}); retrying in {delay}s")
            step_log(step, f"  underlying: {msg.splitlines()[0][:300]}")
            last_err = e
            time.sleep(delay)
    # Unreachable (loop either returns or raises), but appeases type-checkers.
    assert last_err is not None
    raise last_err


def _assign_connection_group_owner(
    client: FabricClient, cfg: dict[str, Any], connection_id: str, step: str,
) -> None:
    """Add the security group as Owner on the connection so all members can manage it."""
    gid = (cfg.get("security_group") or {}).get("object_id")
    if not gid:
        return
    role = "Owner"
    try:
        assignments = client.get_paged(f"/connections/{connection_id}/roleAssignments")
    except RuntimeError as e:
        step_log(step, f"WARN could not list role assignments on connection {connection_id}: {e}")
        return
    if any(a.get("principal", {}).get("id") == gid and a.get("role") == role for a in assignments):
        step_log(step, f"Group {gid} already {role} on connection {connection_id}")
        return
    client.post(
        f"/connections/{connection_id}/roleAssignments",
        {"principal": {"id": gid, "type": "Group"}, "role": role},
    )
    step_log(step, f"Granted group {gid} '{role}' on connection {connection_id}")


def step_5_1(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    return _create_connection(
        client, cfg, cfg["connections"]["source"],
        resolve_gateway_id(client, cfg, "opdg", "5.1"),
        "OnPremisesGateway", "5.1",
    )


def step_5_2(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    # The VDG ADLS connector does not support WorkspaceIdentity (only Key/OAuth2/SAS/SP).
    # WorkspaceIdentity is supported only on ShareableCloud. We create a cloud connection
    # with allowConnectionUsageInGateway=true so it can be consumed by pipeline activities
    # that route through the OPDG/VDG that the workspace has access to. The VDG id is
    # resolved here only to validate the workspace can see it.
    resolve_gateway_id(client, cfg, "vdg", "5.2")
    return _create_connection(
        client, cfg, cfg["connections"]["target"],
        None, "ShareableCloud", "5.2",
        allow_connection_usage_in_gateway=True,
    )


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


def step_6(client: FabricClient, cfg: dict[str, Any]) -> dict[str, Any]:
    ws = require_workspace(client, cfg, "6")
    src_conn = require_connection(client, cfg["connections"]["source"]["name"], "6")
    tgt_conn = require_connection(client, cfg["connections"]["target"]["name"], "6")
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
        step_log("6", f"Updated pipeline '{name}' (id={existing['id']})")
        return existing
    item = client.post(
        f"/workspaces/{ws['id']}/items",
        {"displayName": name, "type": "DataPipeline", "definition": definition},
    )
    step_log("6", f"Created pipeline '{name}' (id={item.get('id')})")
    return item


def step_7(client: FabricClient, cfg: dict[str, Any], timeout: int) -> str:
    ws = require_workspace(client, cfg, "7")
    pipeline = find_pipeline(client, ws["id"], cfg["pipeline"]["name"])
    if not pipeline:
        raise SystemExit(f"[7] Pipeline '{cfg['pipeline']['name']}' not found. Run step 6 first.")
    resp = client.request(
        "POST", f"/workspaces/{ws['id']}/items/{pipeline['id']}/jobs/instances?jobType=Pipeline"
    )
    location = resp.headers.get("Location")
    if not location:
        raise RuntimeError("Pipeline run did not return a Location header to poll")
    step_log("7", f"Pipeline run triggered; polling {location}")
    deadline = time.time() + timeout
    while time.time() < deadline:
        status_obj = client.get(location)
        status = status_obj.get("status", "Unknown")
        step_log("7", f"  status={status}")
        if status in {"Completed", "Failed", "Cancelled", "Deduped"}:
            step_log("7", f"Pipeline final status: {status}")
            if status != "Completed":
                fr = status_obj.get("failureReason") or {}
                if fr:
                    step_log("7", f"  errorCode={fr.get('errorCode')}")
                    step_log("7", f"  message={fr.get('message')}")
                step_log("7", f"  full job instance: {json.dumps(status_obj, indent=2)}")
            return status
        time.sleep(10)
    raise TimeoutError(f"Pipeline did not finish within {timeout}s")


# ---------------------------------------------------------------------------
# Status & orchestration
# ---------------------------------------------------------------------------


def step_status(client: FabricClient, cfg: dict[str, Any]) -> None:
    ws = find_workspace(client, cfg["workspace"]["name"], cfg["workspace"].get("id"))
    step_log("status", f"workspace: {'OK ' + ws['id'] if ws else 'MISSING'}")
    if ws:
        gid = cfg["security_group"]["object_id"]
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
    pgid = (cfg.get("platform_gateway_security_group") or {}).get("object_id")
    team_gid = cfg["security_group"]["object_id"]
    for label, which in (("OPDG", "opdg"), ("VDG", "vdg")):
        try:
            gid_gw = resolve_gateway_id(client, cfg, which, "status")
        except SystemExit as e:
            step_log("status", f"{label}: {e}")
            continue
        try:
            assignments = client.get_paged(f"/gateways/{gid_gw}/roleAssignments")
            if pgid:
                has = any(
                    a.get("principal", {}).get("id") == pgid and a.get("role") == "Admin"
                    for a in assignments
                )
                step_log("status", f"{label} Admin for platform gateway group: {'OK' if has else 'MISSING'}")
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


def step_1(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Fabric admin bootstrap: gateway Admin grants + tenant-setting allow-list."""
    step_1_1(client, cfg)
    step_1_2(client, cfg)
    step_1_3(client, cfg)


def step_3(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Platform SPN: create workspace and grant team secgrp + team SPN Contributor on it."""
    step_3_1(client, cfg)
    step_3_2(client, cfg)  # team secgrp -> workspace Contributor
    step_3_3(client, cfg)  # team SPN direct Contributor (belt-and-braces, no-op if oid not set)


def step_4(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Platform SPN: federate gateway access — team secgrp ConnectionCreatorWithResharing on OPDG + VDG."""
    step_4_1(client, cfg)
    step_4_2(client, cfg)


def step_5(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Team SPN: create the SQL source + ADLS target connections."""
    step_5_1(client, cfg)
    step_5_2(client, cfg)


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


STEPS = {
    "1": lambda c, cfg, _: (require_identity(c, "1", "Fabric admin"), step_1(c, cfg)),
    "2": lambda c, cfg, _: (require_identity(c, "2", "Platform SPN"), step_2(c, cfg)),
    "3": lambda c, cfg, _: (require_identity(c, "3", "Platform SPN"), step_3(c, cfg)),
    "4": lambda c, cfg, _: (require_identity(c, "4", "Platform SPN"), step_4(c, cfg)),
    "5": lambda c, cfg, _: (require_identity(c, "5", "Team SPN"), step_5(c, cfg)),
    "6": lambda c, cfg, _: (require_identity(c, "6", "Team SPN"), step_6(c, cfg)),
    "7": lambda c, cfg, args: (require_identity(c, "7", "Team SPN"), step_7(c, cfg, args.timeout)),
    "status": lambda c, cfg, _: step_status(c, cfg),
    "tenant-settings": lambda c, cfg, _: step_tenant_settings(c, cfg),
}

ALL_ORDER = ["1", "2", "3", "4", "5", "6", "7"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("step", choices=[*STEPS.keys(), "all"], help="Step to run")
    parser.add_argument("config", type=Path, help="Path to environment YAML config")
    parser.add_argument(
        "--timeout", type=int, default=900, help="Pipeline run polling timeout in seconds (step 7)"
    )
    args = parser.parse_args()

    cfg = yaml.safe_load(args.config.read_text())
    cfg["_cfg_path"] = args.config
    _load_state_into_cfg(cfg, args.config)
    client = FabricClient()

    if args.step == "all":
        for s in ALL_ORDER:
            STEPS[s](client, cfg, args)
        return 0
    STEPS[args.step](client, cfg, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
