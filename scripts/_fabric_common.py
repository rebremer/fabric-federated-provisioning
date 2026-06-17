"""
Shared Fabric provisioning library used by the persona scripts:

    scripts/admin/bootstrap.py
    scripts/platform/_common.py
    scripts/platform/integration.py
    scripts/workspace/integration.py

This module owns everything that is *not* persona-specific:
  - low-level HTTP clients (FabricClient, ArmClient) with DefaultAzureCredential
  - identity / logging helpers (step_log, require_identity, whoami)
  - YAML config loading (load_config)
  - Fabric lookups (workspace / capacity / connection / pipeline / gateway)
  - generic gateway role assignment (used by admin step 1.3 and platform step 2.3)
  - on-premises gateway credential encryption (RSA-OAEP-SHA256 + AES-CBC + HMAC)
  - generic connection creation (Basic / Key / ServicePrincipal credentials,
    SQL / ADLS Gen2 connection details, retry on transient upstream errors)

Per-persona scripts import from here and add only the steps unique to their slice.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import requests
import yaml
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FABRIC_BASE = "https://api.fabric.microsoft.com/v1"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
ARM_BASE = "https://management.azure.com"
ARM_SCOPE = "https://management.azure.com/.default"

# Built-in Azure RBAC role definition GUIDs (stable across tenants).
AZURE_ROLE_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"

# Repo root = parent of scripts/.
REPO_ROOT = Path(__file__).resolve().parent.parent


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


def require_identity(client: FabricClient, step: str, role: str) -> None:
    """Print the active Fabric identity so the operator can confirm the right login is in use."""
    step_log(step, f"acting as {role}: {client.whoami()}")


# ---------------------------------------------------------------------------
# Config I/O
# ---------------------------------------------------------------------------
#
# Each persona YAML is read independently. There is no shared state file: every
# step rediscovers Fabric ids by name (workspace -> GET /v1/workspaces, capacity
# -> GET /v1/capacities) so that all three persona scripts are idempotent and
# can be re-run from name alone, in any order.


def load_config(cfg_path: Path) -> dict[str, Any]:
    """Load a persona YAML and attach `_cfg_path` for diagnostics."""
    cfg = yaml.safe_load(cfg_path.read_text()) or {}
    cfg["_cfg_path"] = cfg_path
    return cfg


def find_capacity(client: FabricClient, name: str) -> dict[str, Any] | None:
    """Look up a Fabric capacity by display name. Returns None if not visible to the caller."""
    return next((c for c in client.get_paged("/capacities") if c.get("displayName") == name), None)



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
        raise SystemExit(f"[{step}] Workspace '{cfg['workspace']['name']}' not found. Run platform step 2.2a first.")
    return ws


def require_connection(client: FabricClient, name: str, step: str) -> dict[str, Any]:
    conn = find_connection(client, name)
    if not conn:
        raise SystemExit(f"[{step}] Connection '{name}' not found. Run the matching step 3.1 first.")
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


def assign_gateway_role(
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


# ---------------------------------------------------------------------------
# Key Vault secret fetch
# ---------------------------------------------------------------------------


def kv_get_secret(vault_url: str, secret_name: str) -> str:
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


# ---------------------------------------------------------------------------
# Generic Fabric connection creation
# ---------------------------------------------------------------------------


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
        password = kv_get_secret(kv["vault_url"], kv["sql_password_secret_name"])
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
        secret = kv_get_secret(kv["vault_url"], secret_name)
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


def assign_connection_group_owner(
    client: FabricClient, cfg: dict[str, Any], connection_id: str, step: str,
) -> None:
    """Add the team workspace-contributor security group as Owner on the connection so all members can manage it."""
    gid = (cfg.get("team_workspace_contributor_security_group") or {}).get("object_id")
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


def create_connection(
    client: FabricClient, cfg: dict[str, Any], conn_cfg: dict[str, Any],
    gateway_id: str | None, connectivity_type: str, step: str,
    *, allow_connection_usage_in_gateway: bool = False,
) -> dict[str, Any]:
    """Idempotent create of a Fabric connection (SQL/ADLS, OPDG/ShareableCloud/VDG)."""
    name = conn_cfg["name"]
    existing = find_connection(client, name)
    if existing:
        step_log(step, f"Connection '{name}' already exists (id={existing['id']})")
        assign_connection_group_owner(client, cfg, existing["id"], step)
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
    assign_connection_group_owner(client, cfg, conn["id"], step)
    return conn
