# Fabric federated workspace + OPDG demo

Single Python script that demos a **federated** Fabric provisioning flow with three personas and **three top-level steps** (each composed of named sub-steps). The Fabric admin runs a one-time bootstrap (tenant allow-list + Azure RG create + gateway Admin grants); a Platform SPN then ARM-creates the Fabric capacity, provisions the workspace, and federates gateway access to team security groups; the Team SPN owns its workspace end-to-end.

## Architecture

```text
                          ┌─────────────────────────────────────────────────┐
                          │                Microsoft Entra ID               │
                          │                                                 │
                          │   platform_workspace_security_group  ──┐        │
                          │     └── Platform SPN ──────────────────┤        │
                          │   platform_gateway_security_group  ────┤        │
                          │     └── Platform SPN ──────────────────┤        │
                          │   team_workspace_contributor_secgrp ───┤        │
                          │     └── Team SPN ──────────────────────┘        │
                          └─────────────────────────────────────────────────┘
                                            ▲          ▲          ▲
                                  member of │ member of│ member of│
            ┌────────────────────┐          │          │          │
            │   Fabric admin     │          │          │          │
            │  (interactive)     │          │          │          │
            └─────────┬──────────┘          │          │          │
                      │ STEP 1 (one-time)   │          │          │
                      │                     │          │          │
                      │ 1.1  tenant settings allow-list (add platform_workspace_secgrp)
                      │ 1.2  Azure: create RG + grant platform_workspace_secgrp Contributor
                      │ 1.3  Fabric: Admin on OPDG (1.3a) + VDG (1.3b) to platform_gateway_secgrp
                      ▼                     │          │          │
            ┌────────────────────┐          │          │          │
            │   Azure subscription          │          │          │
            │  ┌──────────────────────────┐ │          │          │
            │  │ RG (capacity.resource_group) ◄────────┘          │
            │  │   Contributor: platform_workspace_secgrp         │
            │  └────────────┬─────────────┘                       │
            └───────────────┼─────────────────────────────────────┘
                            │                                     │
                ┌───────────▼─────────────┐                       │
                │     Platform SPN        │                       │
                └───────────┬─────────────┘                       │
                            │ STEP 2                              │
                            │                                     │
                            │ 2.1  ARM: PUT Microsoft.Fabric/capacities (F2) + self-assign Admin
                            │ 2.2  Fabric: create workspace (2.2a), grant team_secgrp + Team SPN
                            │             Contributor (2.2b + 2.2c)
                            │ 2.3  Fabric: grant team_secgrp ConnectionCreator on
                            │             OPDG (2.3a) + VDG (2.3b)
                            ▼                                     │
            ┌──────────────────────────────────────────────┐      │
            │              Microsoft Fabric tenant         │      │
            │                                              │      │
            │   ┌──────────────────────────────────────┐   │      │
            │   │ Capacity (F2)                        │   │      │
            │   │   admin: Platform SPN                │   │      │
            │   └────────────────┬─────────────────────┘   │      │
            │                    │ bound to                │      │
            │   ┌────────────────▼─────────────────────┐   │      │
            │   │ Workspace                            │   │      │
            │   │   Contributor: team_secgrp, Team SPN │◄──┼──────┘
            │   └────────────────┬─────────────────────┘   │
            │                    │                         │   STEP 3
            │   ┌────────────────▼─────────────────────┐   │
            │   │ 3.1a OnPrem SQL connection (OPDG)    │   │
            │   │ 3.1b ADLS Gen2 connection (ShareableCloud,
            │   │      usable in OPDG/VDG)             │   │
            │   │ 3.2  DataPipeline (Copy: SQL→Parquet)│   │
            │   │ 3.3  Pipeline run (polled)           │   │
            │   └────────┬───────────────────┬─────────┘   │
            │            │                   │             │
            │   ┌────────▼─────────┐  ┌──────▼─────────┐   │
            │   │ OPDG             │  │ VDG (VNet GW)  │   │
            │   │   Admin: pf-gw   │  │   Admin: pf-gw │   │
            │   │   CC: team_sg    │  │   CC: team_sg  │   │
            │   └────────┬─────────┘  └────────────────┘   │
            └────────────┼─────────────────────────────────┘
                         │                                 ▲
                         │ on-prem / private SQL           │
                         ▼                                 │
                  ┌─────────────────┐               ┌──────┴────────┐
                  │ SQL source      │               │ ADLS Gen2     │
                  │ (AdventureWorks)│ ── pipeline ─►│ target (parquet)
                  └─────────────────┘    (3.3)      └───────────────┘
```

Three identities, three handoffs, zero shared secrets. Each persona only has the Azure / Fabric / data permissions needed for its own slice; the script enforces this with `require_identity` at every step boundary.

## Personas

| # | Persona | Scope |
|---|---|---|
| **1** | **Fabric admin** (one-time bootstrap) | Runs all of 1.1 + 1.2 + 1.3 in one command. After step 1 the Fabric admin is no longer in the loop. |
| 1.1 | Fabric admin — *tenant allow-list* | Adds `platform_workspace_security_group` to the tenant-setting allow-list for "Service principals can create workspaces, connections, and deployment pipelines" (Fabric tenant-settings Preview API, mandatory — setting names configured under `tenant_settings.enabled_setting_names` in YAML). |
| 1.2 | Fabric admin — *Azure RG + Contributor* | Creates the Azure resource group named in `capacity.resource_group` and grants `platform_workspace_security_group` `Contributor` on it. Replaces the previous manual `az group create` + `az role assignment create` prereq. Requires Owner (or Contributor + User Access Administrator) on the subscription. |
| 1.3 | Fabric admin — *gateway Admin* | Grants `platform_gateway_security_group` `Admin` on the OPDG (1.3a) + VDG (1.3b). Admin is required in practice; lower roles return 403 `InsufficientPermissionsToManageGateway` despite what the docs say. |
| **2** | **Platform SPN** | Runs all of 2.1 + 2.2 + 2.3 in one command. |
| 2.1 | Platform SPN — *Fabric capacity* | ARM-creates `Microsoft.Fabric/capacities/<name>` (default `F2`) in the RG provisioned by 1.2, and self-assigns capacity Admin (`administration.members`, a superset of Contributor). Idempotent: re-running PATCHes admins if the capacity already exists. |
| 2.2 | Platform SPN — *workspace lifecycle* | Creates the workspace bound to the capacity (2.2a); grants `team_workspace_contributor_security_group` `Contributor` on it (2.2b); grants the team SPN directly `Contributor` on it (2.2c; no-op if `workspace.spn_object_id` is unset). |
| 2.3 | Platform SPN — *gateway federation* | Grants `team_workspace_contributor_security_group` `ConnectionCreator` (need-to-know; not `ConnectionCreatorWithResharing`, so the Team SPN cannot reshare gateway access) on OPDG (2.3a) + VDG (2.3b). Skip 2.3 for a workspace that doesn't need gateway access. |
| **3** | **Team SPN** | Runs all of 3.1 + 3.2 + 3.3 in one command. |
| 3.1 | Team SPN — *connections* | Creates the SQL source connection on the OPDG (3.1a) and the ADLS target ShareableCloud connection (3.1b). |
| 3.2 | Team SPN — *pipeline* | Creates / updates the copy pipeline. |
| 3.3 | Team SPN — *run pipeline* | Triggers the pipeline run and polls to completion. |

After step 1, onboarding a new team workspace = the Platform SPN running `python scripts/provision_fabric.py 2 config/<new>.yaml`, then the Team SPN running `... 3 ...`.

## Prerequisites (exist before running the script)

- SQL source database (demo uses Azure SQL + AdventureWorksLT)
- ADLS Gen2 target storage account
- On-premises data gateway and virtual (VNet) data gateway
- Three Entra ID security groups (the same Platform SPN can be a member of both platform groups):
  - **`platform_workspace_security_group`** containing the Platform SPN — tenant-setting allow-listed by step 1.1 and granted `Contributor` on the capacity RG by step 1.2
  - **`platform_gateway_security_group`** containing the Platform SPN — granted `Admin` on OPDG + VDG by step 1.3
  - **`team_workspace_contributor_security_group`** containing the Team SPN — granted `Storage Blob Data Contributor` on the target ADLS account
- The Fabric admin running step 1 needs:
  - **Fabric service administrator** role (for 1.1 tenant-settings + 1.3 gateway role assignments) and `Tenant.ReadWrite.All`
  - On the Azure subscription named in `capacity.subscription_id`: **Owner** — or **Contributor + User Access Administrator** — so step 1.2 can both create the RG and grant the security group `Contributor` on it. Plain Contributor alone is *not* sufficient (it can create the RG but not the role assignment); the script prints a clear 403 message naming the missing permission if so.
- Azure Key Vault holding the SQL password and the Team SPN client secret; the Team SPN has `Key Vault Secrets User`

No manual `az group create`, no manual `az role assignment create`, and no manual Fabric-portal "Contributors on capacity" step is required — step 1.2 handles RG + role, and step 2.1 self-assigns capacity Admin via ARM (a superset of Contributor).

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

Edit [config/prod-01.example.yaml](config/prod-01.example.yaml) to see the schema. Inline comments document each field. `team_workspace_contributor_security_group`, `platform_workspace_security_group`, `platform_gateway_security_group`, and `capacity` are all required.

> Secrets (SQL password, SPN client secrets) live in Azure Key Vault — never in this repo.
> `prompt.txt` is also git-ignored; use [prompt.example.txt](prompt.example.txt) as a starting point.

## Run

```powershell
# Step 1 — Fabric admin (one-time bootstrap)
# 1.1 tenant allow-list, 1.2 RG create + Contributor, 1.3 gateway Admin on OPDG + VDG.
# Discover the exact tenant setting name(s) for your tenant with:
#   python scripts/provision_fabric.py tenant-settings config/prod-01.yaml
az login
python scripts/provision_fabric.py 1   config/prod-01.yaml   # 1.1 + 1.2 + 1.3
# (or run a single sub-step, e.g. just create the RG + role:)
# python scripts/provision_fabric.py 1.2 config/prod-01.yaml

# Step 2 — Platform SPN
az logout
az login --service-principal --username <platform-app-id> --tenant <tenant-id> --password <secret>
python scripts/provision_fabric.py 2 config/prod-01.yaml     # 2.1 capacity + 2.2 workspace + 2.3 gateway federation

# Step 3 — Team SPN (member of team_workspace_contributor_security_group)
az logout
az login --service-principal --username <team-app-id> --tenant <tenant-id> --password <secret>
python scripts/provision_fabric.py 3 config/prod-01.yaml     # 3.1 connections + 3.2 pipeline + 3.3 run pipeline
```

Helpers:

```powershell
python scripts/provision_fabric.py status          config/prod-01.yaml   # show what exists
python scripts/provision_fabric.py tenant-settings config/prod-01.yaml   # list tenant settings (Fabric admin)
python scripts/provision_fabric.py all             config/prod-01.yaml   # run 1→2→3 as a single identity (admin-style demo only)
```

Every step is idempotent. Step 3.1 auto-retries `POST /connections` on transient upstream-data-source errors (e.g. Azure SQL serverless DB resuming from pause, gateway `DM_GWPipeline_Gateway_DataSourceAccessError`) with `10s -> 30s -> 60s` backoff. Step 3.2 updates the pipeline definition each run, so YAML changes to `pipeline.*` always propagate.
