# Fabric federated workspace + OPDG demo

Single Python script that demos a **federated** Fabric provisioning flow with three personas and six steps. The Fabric admin runs only a one-time gateway bootstrap; a Platform SPN then provisions the workspace and federates gateway access to team security groups, and the Team SPN owns its workspace end-to-end.

## Personas

| # | Persona | Scope |
|---|---|---|
| 1 | **Fabric admin** | One-time: in the Fabric Admin portal, adds the *platform workspace-creator* secgrp to (a) the allow-list for *"Service principals can create workspaces"* and (b) Contributor on the target Fabric capacity; then grants the *platform gateway-admin* secgrp `Admin` on OPDG + VDG. |
| 2 | **Platform SPN** — *workspace lifecycle* | Creates the workspace; grants the *team* secgrp + team SPN `Contributor` on the workspace. |
| 3 | **Platform SPN** — *gateway federation* | Grants the *team* secgrp `ConnectionCreator` on OPDG + VDG. Skip this step for a workspace that doesn't need gateway access. |
| 4-6 | **Team SPN** (member of team secgrp) | Creates SQL source + ADLS target connections, creates the copy pipeline, runs it. |

After step 1, the Fabric admin is no longer in the loop: onboarding a new team workspace = the Platform SPN running steps 2 (+ 3 if gateways are needed) against a new YAML.

## Prerequisites (exist before running the script)

- SQL source database (demo uses Azure SQL + AdventureWorksLT)
- ADLS Gen2 target storage account
- On-premises data gateway and virtual (VNet) data gateway
- Three Entra ID security groups (the same Platform SPN can be a member of both platform groups):
  - **Platform workspace-creator secgrp** containing the Platform SPN — allow-listed by tenant setting *"Service principals can create workspaces"*, and added as **Contributor** on the Fabric capacity that new workspaces are bound to (`workspace.capacity_id` in YAML). Without the capacity Contributor role, step 2.1 fails with `InsufficientPermissionsOverCapacity`. *(Future: also needs rights to create new capacities — out of scope here.)*
  - **Platform gateway-admin secgrp** containing the Platform SPN — granted `Admin` on OPDG + VDG in step 1
  - **Team secgrp** containing the Team SPN — granted `Storage Blob Data Contributor` on the target ADLS account
- Azure Key Vault holding the SQL password and the Team SPN client secret; the Team SPN has `Key Vault Secrets User`

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configure

Copy the template and fill in your values — the real file is git-ignored:

```powershell
Copy-Item config/prod-01.example.yaml config/prod-01.yaml
```

Edit [config/prod-01.example.yaml](config/prod-01.example.yaml) to see the schema. Inline comments document each field. `security_group` (team), `platform_workspace_security_group`, and `platform_gateway_security_group` are all required.

> Secrets (SQL password, SPN client secrets) live in Azure Key Vault — never in this repo.
> `prompt.txt` is also git-ignored; use [prompt.example.txt](prompt.example.txt) as a starting point.

## Run

```powershell
# Step 1 — Fabric admin (one-time bootstrap)
# Manual prereqs (Fabric Admin portal, no public REST API):
#   - Tenant settings: enable "Service principals can create workspaces, connections,
#     and deployment pipelines" for the *platform workspace-creator* security group.
#   - Capacity settings: add the *platform workspace-creator* secgrp as Contributor
#     on the Fabric capacity bound to new workspaces (workspace.capacity_id).
# Without either, step 2.1 (workspace create) fails 401/403 or InsufficientPermissionsOverCapacity.
az login
python scripts/provision_fabric.py 1 config/prod-01.yaml

# Steps 2-3 — Platform SPN
az logout
az login --service-principal --username <platform-app-id> --tenant <tenant-id> --password <secret>
python scripts/provision_fabric.py 2 config/prod-01.yaml   # create workspace + grant team Contributor
python scripts/provision_fabric.py 3 config/prod-01.yaml   # grant team secgrp ConnectionCreator on OPDG + VDG

# Steps 4-6 — Team SPN (member of the team security group)
az logout
az login --service-principal --username <team-app-id> --tenant <tenant-id> --password <secret>

python scripts/provision_fabric.py 4 config/prod-01.yaml   # source + target connections
python scripts/provision_fabric.py 5 config/prod-01.yaml   # create/update pipeline
python scripts/provision_fabric.py 6 config/prod-01.yaml   # run pipeline (polls)
```

Helpers:

```powershell
python scripts/provision_fabric.py status config/prod-01.yaml   # show what exists
python scripts/provision_fabric.py all    config/prod-01.yaml   # run 1→6 as a single identity (admin-style demo only)
```

Every step is idempotent. Step 5 updates the pipeline definition each run, so YAML changes to `pipeline.*` always propagate.
