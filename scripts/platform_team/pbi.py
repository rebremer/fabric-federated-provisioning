"""
Platform team (M) — PBI variant (STUB — not implemented).

Sibling of `integration.py` for a Power BI / semantic-model platform team.
Reuses the same variant-independent base (capacity + workspace + RBAC) from
`platform_team/_common.py`; differs in what (if anything) it adds in step 2.3.

The PBI variant typically:
  - DOES create a Fabric capacity (2.1) and a team workspace (2.2) just like the
    integration variant
  - DOES NOT grant OPDG/VDG ConnectionCreator (no on-prem data path) — so the
    integration-specific step 2.3a/2.3b are skipped
  - MAY add PBI-specific federation steps here, e.g.:
      * grant the team secgrp Member (or Admin) on a shared dataflow workspace
      * register the workspace as a domain workspace under a Fabric Domain
      * grant the team secgrp access to a shared OneLake shortcut source
      * assign sensitivity-label policies on the workspace
  - MAY pin the capacity SKU higher than F2 (PBI workloads often want F8/F16+)

Outline of what an implementation would look like:

    from _fabric_common import FabricClient, load_config, require_identity, step_log
    from platform_team._common import step_2_1, step_2_2

    def step_2_3_pbi(client, cfg):
        # e.g. assign domain, attach shared dataflow workspace, etc.
        ...

    def step_2(client, cfg):
        step_2_1(client, cfg)
        step_2_2(client, cfg)
        step_2_3_pbi(client, cfg)

    STEPS = {
        "2":   lambda c, cfg: (require_identity(c, "2",   "PBI Platform SPN"), step_2(c, cfg)),
        "2.1": lambda c, cfg: (require_identity(c, "2.1", "PBI Platform SPN"), step_2_1(c, cfg)),
        "2.2": lambda c, cfg: (require_identity(c, "2.2", "PBI Platform SPN"), step_2_2(c, cfg)),
        "2.3": lambda c, cfg: (require_identity(c, "2.3", "PBI Platform SPN"), step_2_3_pbi(c, cfg)),
    }

Config file would live at:
    config/platform_team/pbi/<env>.yaml

It would omit the `gateways:` section (no OPDG/VDG) and may add PBI-specific
keys (e.g. `domain:`, `sensitivity_labels:`, `shared_dataflow_workspace:`).
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "scripts/platform_team/pbi.py is a stub — not implemented yet.\n"
        "See the module docstring for an outline of what this would do.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
