# Fabric federated workspace + OPDG demo

Single Python script that demos a **federated** Fabric provisioning flow with three personas and **seven steps**. The Fabric admin runs only a one-time gateway bootstrap; a Platform SPN then ARM-creates the Fabric capacity, provisions the workspace, and federates gateway access to team security groups; the Team SPN owns its workspace end-to-end.

## Personas

| # | Persona | Scope |
|---|---|---|
| 1 | **Fabric admin** | One-time: grants the *platform gateway-admin* secgrp `Admin` on OPDG + VDG (1.1, 1.2 — Admin is required in practice; lower roles get 403 `InsufficientPermissionsToManageGateway` despite what the docs say); adds the *platform workspace-creator* secgrp to the tenant-setting allow-list for SPN workspace creation via the Preview REST API (1.3, mandatory — setting names configured under `tenant_settings.enabled_setting_names` in YAML). No manual capacity Contributor portal step — step 2 handles capacity provisioning end-to-end via ARM. |
| 2 | **Platform SPN** — *Fabric capacity* | ARM-creates `Microsoft.Fabric/capacities/<name>` (default `F2`) and self-assigns capacity Admin (`administration.members`), which is a superset of "Contributor" and unlocks workspace-to-capacity binding in step 3. Idempotent: re-running PATCHes admins if the capacity already exists. |
| 3 | **Platform SPN** — *workspace lifecycle* | Creates the workspace (bound to the capacity from step 2); grants the *team* secgrp + team SPN `Contributor` on the workspace. |
| 4 | **Platform SPN** — *gateway federation* | Grants the *team* secgrp `ConnectionCreatorWithResharing` on OPDG + VDG. Skip this step for a workspace that doesn't need gateway access. |
| 5-7 | **Team SPN** (member of team secgrp) | Creates SQL source + ADLS target connections, creates the copy pipeline, runs it. |

After step 1, the Fabric admin is no longer in the loop: onboarding a new team workspace = the Platform SPN running steps 2 → 3 (+ 4 if gateways are needed) against a new YAML.

## Prerequisites (exist before running the script)

- SQL source database (demo uses Azure SQL + AdventureWorksLT)
- ADLS Gen2 target storage account
- On-premises data gateway and virtual (VNet) data gateway
- Three Entra ID security groups (the same Platform SPN can be a member of both platform groups):
  - **Platform workspace-creator secgrp** containing the Platform SPN — tenant-setting allow-listed by step 1.3 for "Service principals can create workspaces"
  - **Platform gateway-admin secgrp** containing the Platform SPN — granted `Admin` on OPDG + VDG in step 1
  - **Team secgrp** containing the Team SPN — granted `Storage Blob Data Contributor` on the target ADLS account
- Azure resource group for the Fabric capacity. **The Platform SPN must have `Contributor` (or at minimum `Microsoft.Fabric/capacities/write`) on this RG** — step 2 PUTs the capacity here. Configure as `capacity.resource_group` in YAML. No manual Fabric-portal "Contributors on capacity" step is required — step 2 self-assigns capacity Admin via ARM (`properties.administration.members`), which is a superset of Contributor. If the role assignment is missing, step 2 fails with a clear `az role assignment create` command you can paste verbatim to fix it.
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

Edit [config/prod-01.example.yaml](config/prod-01.example.yaml) to see the schema. Inline comments document each field. `security_group` (team), `platform_workspace_security_group`, `platform_gateway_security_group`, and `capacity` are all required.

> Secrets (SQL password, SPN client secrets) live in Azure Key Vault — never in this repo.
> `prompt.txt` is also git-ignored; use [prompt.example.txt](prompt.example.txt) as a starting point.

## Run

```powershell
# Step 1 — Fabric admin (one-time bootstrap)
# Scripted by 1.3 (mandatory, configured in YAML under tenant_settings.enabled_setting_names):
#   Tenant settings → add the *platform workspace-creator* secgrp to the allow-list
#   for "Service principals can create workspaces, connections, and deployment pipelines".
# Discover the exact tenant setting name(s) for your tenant with:
#   python scripts/provision_fabric.py tenant-settings config/prod-01.yaml
az login
python scripts/provision_fabric.py 1 config/prod-01.yaml

# Steps 2-4 — Platform SPN
az logout
az login --service-principal --username <platform-app-id> --tenant <tenant-id> --password <secret>
python scripts/provision_fabric.py 2 config/prod-01.yaml   # ARM-create Fabric capacity + self-admin
python scripts/provision_fabric.py 3 config/prod-01.yaml   # create workspace + grant team Contributor
python scripts/provision_fabric.py 4 config/prod-01.yaml   # grant team secgrp ConnectionCreatorWithResharing on OPDG + VDG

# Steps 5-7 — Team SPN (member of the team security group)
az logout
az login --service-principal --username <team-app-id> --tenant <tenant-id> --password <secret>

python scripts/provision_fabric.py 5 config/prod-01.yaml   # source + target connections
python scripts/provision_fabric.py 6 config/prod-01.yaml   # create/update pipeline
python scripts/provision_fabric.py 7 config/prod-01.yaml   # run pipeline (polls)
```

Helpers:

```powershell
python scripts/provision_fabric.py status          config/prod-01.yaml   # show what exists
python scripts/provision_fabric.py tenant-settings config/prod-01.yaml   # list tenant settings (Fabric admin)
python scripts/provision_fabric.py all             config/prod-01.yaml   # run 1→7 as a single identity (admin-style demo only)
```

Every step is idempotent. Step 5 auto-retries `POST /connections` on transient upstream-data-source errors (e.g. Azure SQL serverless DB resuming from pause, gateway `DM_GWPipeline_Gateway_DataSourceAccessError`) with `10s -> 30s -> 60s` backoff. Step 6 updates the pipeline definition each run, so YAML changes to `pipeline.*` always propagate.
