"""Ensure users holding Tier 0 privileged roles are not stale."""

from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    TIER_0_ROLE_TEMPLATE_IDS,
)

DEFAULT_STALE_PRIVILEGED_ACCOUNT_DAYS = 90


class entra_privileged_role_users_not_stale(Check):
    """Ensure users holding Tier 0 privileged roles have signed in recently.

    Privileged accounts nobody uses are rarely monitored yet keep their full
    power, making them an attractive target and a common leftover after role
    changes. Ported from Maester test MT.1029.

    - PASS: The user holding a Tier 0 role signed in within the configured
      threshold (``stale_privileged_account_days``, default 90).
    - FAIL: The user has not signed in for longer than the threshold, or has
      never signed in at all.
    - MANUAL: Sign-in activity could not be read for the tenant (missing
      Entra ID P1 licence or permission), so the check cannot be evaluated.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        audit_config = entra_client.audit_config or {}
        stale_days = audit_config.get(
            "stale_privileged_account_days", DEFAULT_STALE_PRIVILEGED_ACCOUNT_DAYS
        )

        if entra_client.privileged_users_sign_in_error:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Entra ID Users",
                resource_id="users",
            )
            report.status = "MANUAL"
            report.status_extended = (
                "Cannot evaluate whether privileged role holders are stale: "
                f"sign-in activity could not be read. {entra_client.privileged_users_sign_in_error} "
                "Check the scanning application's permissions and any Microsoft "
                "Graph API errors in the scan log."
            )
            findings.append(report)
            return findings

        for user in entra_client.users.values():
            tier_0_roles = set(user.directory_roles_ids) & TIER_0_ROLE_TEMPLATE_IDS
            tier_0_roles |= (
                set(user.eligible_tier_0_role_template_ids) & TIER_0_ROLE_TEMPLATE_IDS
            )
            if not tier_0_roles:
                continue

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.id,
            )

            last_sign_in = user.last_sign_in_date_time
            if last_sign_in is None:
                report.status = "FAIL"
                report.status_extended = (
                    f"User '{user.name}' holds a Tier 0 privileged role and has no "
                    f"recorded sign-in; the account is treated as stale (threshold {stale_days} days)."
                )
            else:
                if last_sign_in.tzinfo is None:
                    last_sign_in = last_sign_in.replace(tzinfo=timezone.utc)
                days_since_sign_in = (datetime.now(timezone.utc) - last_sign_in).days
                if days_since_sign_in > stale_days:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User '{user.name}' holds a Tier 0 privileged role and has not "
                        f"signed in for {days_since_sign_in} days (threshold {stale_days} days)."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"User '{user.name}' holds a Tier 0 privileged role and signed in "
                        f"{days_since_sign_in} days ago."
                    )
            findings.append(report)

        return findings
