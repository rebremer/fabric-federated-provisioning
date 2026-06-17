"""
Platform team (M) — INTEGRATION variant.

Maps to blog section 2.2 "Platform team (M) — the workspace factory" for the
integration platform: the variant that provisions workspaces talking to on-prem
sources through the OPDG + VDG.

Composes the variant-independent base (capacity + workspace + Contributor grants)
with the integration-specific gateway federation step:

  2.1  ARM-create Fabric capacity (from platform_team/_common.py)
  2.2  Create workspace + grant team secgrp + team SPN Contributor (from _common.py)
  2.3  INTEGRATION-only — grant team_workspace_contributor_security_group
       ConnectionCreator (need-to-know, NOT WithResharing) on OPDG (2.3a) + VDG (2.3b)
       so the Team SPN can create gateway connections in workspace_team/integration.py
       step 3.1 without the Platform SPN being involved.

Auth: `az login --service-principal --username <platform-app-id>` for an
*integration* Platform SPN that is a member of BOTH
platform_workspace_security_group and platform_gateway_security_group.

Usage:
    python scripts/platform_team/integration.py 2   config/platform_team/integration/prod-01.yaml
    python scripts/platform_team/integration.py 2.1 config/platform_team/integration/prod-01.yaml
    python scripts/platform_team/integration.py 2.2 config/platform_team/integration/prod-01.yaml
    python scripts/platform_team/integration.py 2.3 config/platform_team/integration/prod-01.yaml

To onboard a second integration workspace (after admin step 1 has been done once
for the platform security group), just point at a new YAML:
    python scripts/platform_team/integration.py 2 config/platform_team/integration/prod-02.yaml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from _fabric_common import (  # noqa: E402
    FabricClient,
    assign_gateway_role,
    load_config,
    require_identity,
)
from platform_team._common import step_2_1, step_2_2  # noqa: E402


# --- Step 2.3: integration-only — gateway federation -------------------
# Grants the team security group ConnectionCreator on the OPDG and VDG so the Team
# SPN can create connections in workspace_team/integration.py step 3.1. Need-to-know:
# ConnectionCreator (NOT ConnectionCreatorWithResharing) — the Team SPN should not be
# able to reshare gateway access with other principals. The platform gateway-admin
# secgrp (Admin role from admin step 1.3) is allowed to assign any role.


def step_2_3a(client: FabricClient, cfg: dict[str, Any]) -> None:
    assign_gateway_role(
        client, cfg, "opdg", "2.3a",
        principal_id=cfg["team_workspace_contributor_security_group"]["object_id"],
        role="ConnectionCreator",
    )


def step_2_3b(client: FabricClient, cfg: dict[str, Any]) -> None:
    assign_gateway_role(
        client, cfg, "vdg", "2.3b",
        principal_id=cfg["team_workspace_contributor_security_group"]["object_id"],
        role="ConnectionCreator",
    )


def step_2_3(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Integration platform: federate gateway access — team secgrp ConnectionCreator on OPDG + VDG."""
    step_2_3a(client, cfg)
    step_2_3b(client, cfg)


def step_2(client: FabricClient, cfg: dict[str, Any]) -> None:
    """Integration platform SPN: capacity (2.1) + workspace + RBAC (2.2) + gateway federation (2.3)."""
    step_2_1(client, cfg)
    step_2_2(client, cfg)
    step_2_3(client, cfg)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


STEPS = {
    "2":   lambda c, cfg: (require_identity(c, "2",   "Integration Platform SPN"), step_2(c, cfg)),
    "2.1": lambda c, cfg: (require_identity(c, "2.1", "Integration Platform SPN"), step_2_1(c, cfg)),
    "2.2": lambda c, cfg: (require_identity(c, "2.2", "Integration Platform SPN"), step_2_2(c, cfg)),
    "2.3": lambda c, cfg: (require_identity(c, "2.3", "Integration Platform SPN"), step_2_3(c, cfg)),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("step", choices=list(STEPS.keys()), help="Sub-step to run")
    parser.add_argument(
        "config", type=Path,
        help="Path to integration platform YAML (e.g. config/platform_team/integration/prod-01.yaml)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    client = FabricClient()
    STEPS[args.step](client, cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
