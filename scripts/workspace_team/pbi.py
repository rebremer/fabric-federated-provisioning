"""
Workspace team (M×N) — PBI variant (STUB — not implemented).

Sibling of `integration.py` for a workspace owned by a Power BI / semantic-model
team. The platform_team/pbi.py variant would have provisioned this workspace
WITHOUT OPDG/VDG ConnectionCreator (no on-prem data path), so step 3.1a / 3.1b
from the integration variant don't apply.

A PBI workspace_team script typically:
  - DOES NOT create OPDG / ShareableCloud connections for SQL/ADLS
  - DOES deploy PBI-specific items into the workspace, e.g.:
      * import .pbix / .bim semantic models via POST /v1/workspaces/{id}/semanticModels
      * deploy paginated reports (.rdl) and PBI reports (.pbir) via /reports
      * configure dataset refresh schedules / refresh on demand
      * register the workspace under a deployment pipeline (Dev / Test / Prod)
      * apply RLS / OLS roles to semantic models from team-owned config
      * publish to an app workspace and grant viewer audiences

Outline of what an implementation would look like:

    from _fabric_common import FabricClient, load_config, require_identity, step_log
    from _fabric_common import require_workspace

    def step_3_1_pbi(client, cfg):
        # POST /v1/workspaces/{id}/semanticModels (definition base64-inline like pipelines).
        ...

    def step_3_2_pbi(client, cfg):
        # Refresh the semantic model: POST /v1/workspaces/{id}/semanticModels/{id}/refreshes
        ...

    def step_3_3_pbi(client, cfg, timeout):
        # Poll the refresh status; equivalent to the integration variant's pipeline poll.
        ...

    STEPS = {
        "3":      lambda c, cfg, args: (require_identity(c, "3",   "PBI Team SPN"), ...),
        "3.1":    lambda c, cfg, _:    (require_identity(c, "3.1", "PBI Team SPN"), step_3_1_pbi(c, cfg)),
        "3.2":    lambda c, cfg, _:    (require_identity(c, "3.2", "PBI Team SPN"), step_3_2_pbi(c, cfg)),
        "3.3":    lambda c, cfg, args: (require_identity(c, "3.3", "PBI Team SPN"), step_3_3_pbi(c, cfg, args.timeout)),
        "status": lambda c, cfg, _:    ...,
    }

Config file would live at:
    config/workspace_team/pbi/<env>.yaml

It would replace the integration variant's `gateways:` / `connections:` /
`pipeline:` sections with PBI-specific keys, e.g.:

    semantic_models:
      - name: sales-mart
        bim_path: artifacts/sales-mart.bim
        rls_roles:
          - name: RegionalManager
            members: [...]
    reports:
      - name: sales-overview
        pbir_path: artifacts/sales-overview/
    refresh:
      schedule: "0 6 * * *"
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "scripts/workspace_team/pbi.py is a stub — not implemented yet.\n"
        "See the module docstring for an outline of what this would do.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
