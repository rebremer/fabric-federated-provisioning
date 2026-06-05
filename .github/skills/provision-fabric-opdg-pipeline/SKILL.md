---
name: provision-fabric-opdg-pipeline
description: 'Maintain and run scripts/provision_fabric.py — a Python demo that (1) provisions a Microsoft Fabric workspace and grants a security group access to the workspace + OPDG + VDG, (2) creates an OPDG SQL source connection and a ShareableCloud ADLS Gen2 target connection as the SPN, (3) creates a Fabric copy pipeline, (4) runs the pipeline. Use when the user wants to scaffold, extend, or execute the OPDG + ShareableCloud + copy-pipeline demo against a YAML config. Assumes ADLS Gen2, OPDG, VDG, security group, SPN, and Key Vault already exist. Trigger keywords: Fabric workspace, OPDG, on-premises data gateway, virtual data gateway, VNet gateway, ADLS Gen2 connection, Fabric pipeline, copy activity, az login, DefaultAzureCredential, demo script.'
argument-hint: 'config/prod-01.yaml'
---

# Provision Fabric Workspace + OPDG Connections + Copy Pipeline

Maintains [scripts/provision_fabric.py](../../../scripts/provision_fabric.py): one Python script that runs the four-step demo against a YAML config.

## Flow

| CLI step | Persona | What it does | Key endpoints |
|---|---|---|---|
| **1** | Fabric admin | Create workspace; grant security group `Contributor` on workspace; (opt) provision workspace identity; grant security group `ConnectionCreator` on OPDG + VDG | `POST /v1/workspaces`, `POST /v1/workspaces/{id}/roleAssignments`, `POST /v1/gateways/{id}/roleAssignments` |
| **2** | SPN (in secgrp) | Create SQL source connection on OPDG; create ShareableCloud ADLS Gen2 target connection (`allowConnectionUsageInGateway=true`); grant secgrp `Owner` on both | `POST /v1/connections`, `POST /v1/connections/{id}/roleAssignments` |
| **3** | SPN | Create or update the copy pipeline (`SQL → ADLS Gen2 Parquet`) | `POST /v1/workspaces/{id}/items`, `POST .../dataPipelines/{id}/updateDefinition` |
| **4** | SPN | Trigger and poll the pipeline run | `POST .../items/{id}/jobs/instances?jobType=Pipeline` |

Fabric base: `https://api.fabric.microsoft.com/v1`. Auth: `DefaultAzureCredential` (scope `https://api.fabric.microsoft.com/.default`). The script prints `acting as ...` at the top of each step so the operator can confirm the right `az` login.

## Prerequisites (NOT created by the script)
- ADLS Gen2 source + target storage accounts
- On-premises data gateway and virtual (VNet) data gateway
- Entra ID security group containing the SPN, granted `Storage Blob Data Contributor` on the target ADLS account (out-of-band)
- SPN with Fabric workspace-create rights and `Key Vault Secrets User` on the KV
- Azure Key Vault holding the SQL password and the SPN client secret

## Files owned by this skill
- [scripts/provision_fabric.py](../../../scripts/provision_fabric.py)
- [config/prod-01.yaml](../../../config/prod-01.yaml)
- [requirements.txt](../../../requirements.txt)

## Demo procedure
```powershell
# Step 1 — Fabric admin
az login
python scripts/provision_fabric.py 1 config/prod-01.yaml

# Steps 2-4 — SPN
az logout
az login --service-principal --username <appid> --tenant <tid> --password <secret>
python scripts/provision_fabric.py 2 config/prod-01.yaml   # connections
python scripts/provision_fabric.py 3 config/prod-01.yaml   # pipeline
python scripts/provision_fabric.py 4 config/prod-01.yaml   # run
```
`status` prints current state of every resource; `all` runs 1→4 as a single identity.

## Idempotency
Every `create_*` helper looks up the object by name first. Step 3 calls `updateDefinition` when the pipeline already exists, so YAML edits to `pipeline.*` propagate without manual deletes.

## Extending
- New connection → add an entry under `connections:` in YAML and a call in `step_2`.
- Different copy activity → edit `build_pipeline_definition()`.
- Polling timeout → `--timeout` CLI flag (applies to step 4).

## Anti-patterns
- Do **not** hard-code IDs or secrets in `provision_fabric.py`; per-env values go in YAML.
- Do **not** add ARM/storage RBAC back into the script — `Storage Blob Data Contributor` on the target ADLS is a prerequisite granted out-of-band.
- Do **not** create ADLS / gateway / SPN / KV resources in the script — those are prerequisites.
- Do **not** swap auth away from `DefaultAzureCredential`.
