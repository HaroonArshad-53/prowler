from datetime import datetime, timedelta, timezone
from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    TIER_0_ROLE_TEMPLATE_IDS,
    User,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

TIER0_ROLE_ID = sorted(TIER_0_ROLE_TEMPLATE_IDS)[0]
OTHER_ROLE_ID = (
    "88d8e3e3-8f55-4a1e-953a-9b2b57cda5f3"  # Directory Readers, not a Tier 0 role
)


def _make_user(user_id, name, role_ids, last_sign_in=None, eligible=None):
    return User(
        id=user_id,
        name=name,
        on_premises_sync_enabled=False,
        directory_roles_ids=list(role_ids),
        last_sign_in_date_time=last_sign_in,
        eligible_tier_0_role_template_ids=list(eligible or []),
    )


class Test_entra_privileged_role_users_not_stale:
    """Tests for the entra_privileged_role_users_not_stale check."""

    def _run(self, users, audit_config=None, sign_in_error=None):
        entra_client = mock.MagicMock()
        entra_client.users = users
        entra_client.audit_config = audit_config
        entra_client.privileged_users_sign_in_error = sign_in_error

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_privileged_role_users_not_stale.entra_privileged_role_users_not_stale import (
                entra_privileged_role_users_not_stale,
            )

            return entra_privileged_role_users_not_stale().execute()

    def test_sign_in_error_manual(self):
        """MANUAL when sign-in activity could not be read for the tenant."""
        error = "Insufficient privileges or missing Entra ID P1 licence to read user sign-in activity."
        result = self._run(users={}, sign_in_error=error)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == "users"
        assert result[0].resource_name == "Entra ID Users"
        assert (
            "Cannot evaluate whether privileged role holders are stale"
            in result[0].status_extended
        )

    def test_no_tier0_users_no_findings(self):
        """No findings when no user holds a Tier 0 role."""
        users = {
            "user1": _make_user(
                "user1",
                "Regular User",
                [OTHER_ROLE_ID],
                datetime.now(timezone.utc) - timedelta(days=400),
            ),
            "user2": _make_user(
                "user2", "No Roles", [], datetime.now(timezone.utc) - timedelta(days=1)
            ),
        }
        result = self._run(users=users)

        assert result == []

    def test_recent_sign_in_pass(self):
        """PASS when the Tier 0 holder signed in within the threshold."""
        users = {
            "admin1": _make_user(
                "admin1",
                "Admin User",
                [TIER0_ROLE_ID],
                datetime.now(timezone.utc) - timedelta(days=10),
            ),
        }
        result = self._run(users=users)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == "admin1"
        assert result[0].resource_name == "Admin User"
        assert "10 days ago" in result[0].status_extended

    def test_stale_sign_in_fail(self):
        """FAIL when the Tier 0 holder has not signed in for the threshold."""
        users = {
            "admin1": _make_user(
                "admin1",
                "Stale Admin",
                [TIER0_ROLE_ID],
                datetime.now(timezone.utc) - timedelta(days=120),
            ),
        }
        result = self._run(users=users)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].resource_id == "admin1"
        assert "120 days" in result[0].status_extended
        assert "threshold 90 days" in result[0].status_extended

    def test_never_signed_in_fail(self):
        """FAIL when the Tier 0 holder has never signed in."""
        users = {
            "admin1": _make_user(
                "admin1", "Never Signed In", [TIER0_ROLE_ID], last_sign_in=None
            ),
        }
        result = self._run(users=users)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "no recorded sign-in" in result[0].status_extended

    def test_custom_threshold(self):
        """The stale_privileged_account_days config value changes the threshold."""
        users = {
            "admin1": _make_user(
                "admin1",
                "Admin User",
                [TIER0_ROLE_ID],
                datetime.now(timezone.utc) - timedelta(days=40),
            ),
        }
        result = self._run(
            users=users, audit_config={"stale_privileged_account_days": 30}
        )

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "threshold 30 days" in result[0].status_extended

    def test_pim_eligible_holder_evaluated(self):
        """PIM-eligible Tier 0 holders are evaluated even without an active assignment."""
        users = {
            "admin1": _make_user(
                "admin1",
                "Eligible Admin",
                [],
                datetime.now(timezone.utc) - timedelta(days=200),
                eligible=[TIER0_ROLE_ID],
            ),
        }
        result = self._run(users=users)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "200 days" in result[0].status_extended

    def test_naive_datetime_handled(self):
        """Naive datetimes are treated as UTC instead of crashing."""
        users = {
            "admin1": _make_user(
                "admin1",
                "Admin User",
                [TIER0_ROLE_ID],
                datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=5),
            ),
        }
        result = self._run(users=users)

        assert len(result) == 1
        assert result[0].status == "PASS"
