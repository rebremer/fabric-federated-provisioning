# Fabric OPDG provisioning demo

Single Python script that demos the four-step flow:

1. **Admin** creates a Fabric workspace and grants the security group access to the workspace + OPDG + VDG.
2. **SPN** (member of the security group) creates the SQL source connection on the OPDG and a ShareableCloud ADLS Gen2 target connection.
3. **SPN** creates the Fabric copy pipeline (`SQL → ADLS Gen2 Parquet`).
4. **SPN** runs the pipeline and polls until completion.

## Prerequisites (exist before running the script)

- SQL source database (demo uses Azure SQL + AdventureWorksLT)
- ADLS Gen2 target storage account
- On-premises data gateway and virtual (VNet) data gateway
- Entra ID security group containing the SPN, granted `Storage Blob Data Contributor` on the target ADLS account
- SPN with rights to create Fabric workspaces
- Azure Key Vault holding the SQL password and the SPN client secret; SPN has `Key Vault Secrets User`

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

Edit [config/prod-01.example.yaml](config/prod-01.example.yaml) to see the schema. Inline comments document each field.

> Secrets (SQL password, SPN client secret) live in Azure Key Vault — never in this repo.
> `prompt.txt` is also git-ignored; use [prompt.example.txt](prompt.example.txt) as a starting point.

## Run

```powershell
# Step 1 — Fabric admin
az login
python scripts/provision_fabric.py 1 config/prod-01.yaml

# Steps 2-4 — SPN (member of the security group)
az logout
az login --service-principal --username <app-id> --tenant <tenant-id> --password <secret>

python scripts/provision_fabric.py 2 config/prod-01.yaml   # source + target connections
python scripts/provision_fabric.py 3 config/prod-01.yaml   # create/update pipeline
python scripts/provision_fabric.py 4 config/prod-01.yaml   # run pipeline (polls)
```

Helpers:

```powershell
python scripts/provision_fabric.py status config/prod-01.yaml   # show what exists
python scripts/provision_fabric.py all    config/prod-01.yaml   # run 1→4 as a single identity
```

Every step is idempotent. Step 3 updates the pipeline definition each run, so YAML changes to `pipeline.*` always propagate.
