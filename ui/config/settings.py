"""Platform configuration loaded directly from environment variables.

Production deployments configure every value through Azure App Service
Configuration > Application Settings (no Azure Key Vault). Locally the same
variables are provided by the environment or ``.env``.

Expected environment variables:

* ``SECRET_KEY`` - Flask session signing key
* ``DATABASE_URL`` - PostgreSQL connection string (required at startup)
* ``FIREWALL_FUNCTION_URL`` (alias ``BASE_URL``) - Azure Functions base URL
* ``FIREWALL_FUNCTION_KEY`` - access key for single-control function endpoints
* ``FULL_ASSESSMENT_KEY`` - access key for ``run_full_assessment``
* ``EXCEL_KEY`` - access key for ``generate_excel_report``
* ``EXECUTIVE_SUMMARY_KEY`` - access key for ``executive_summary``
* ``APP_INSIGHTS_CONNECTION_STRING`` - Application Insights ingestion string
* ``APP_INSIGHTS_ENABLED`` - toggle Application Insights telemetry
* ``NETSEC_FW_HOST`` / ``NETSEC_FW_USERNAME`` / ``NETSEC_FW_PASSWORD`` - the
  firewall the NetSec Execution Agent targets (see
  ``netsec_execution.connector.panos`` for the full NETSEC_FW_* set)
* ``NETSEC_FW_DRY_RUN`` - ``1`` previews playbook changes, ``0`` applies them
* ``NETSEC_WORKBOOK_DIR`` - where uploaded playbook workbooks are stored
* ``NETSEC_MAX_ROWS`` - cap on data rows executed per playbook run
"""

import os


def env(name, default=""):
    value = os.environ.get(name)
    return default if value is None else value.strip()


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


SECRET_KEY = env(
    "SECRET_KEY",
    "ltm-security-platform-dev-secret-key-change-me",
)

DATABASE_URL = env("DATABASE_URL")

BASE_URL = env(
    "FIREWALL_FUNCTION_URL",
    env(
        "BASE_URL",
        (
            "https://network-security-firewall-agent-frcrcqg0ejaddte2."
            "southindia-01.azurewebsites.net/api"
        ),
    ),
)

FUNCTION_KEY = env(
    "FIREWALL_FUNCTION_KEY",
    "PLACEHOLDER_REPLACE_WITH_YOUR_FUNCTION_KEY",
)

FULL_ASSESSMENT_KEY = env(
    "FULL_ASSESSMENT_KEY",
    "PLACEHOLDER_REPLACE_WITH_YOUR_FULL_ASSESSMENT_KEY",
)

EXCEL_KEY = env(
    "EXCEL_KEY",
    "PLACEHOLDER_REPLACE_WITH_YOUR_EXCEL_KEY",
)

EXECUTIVE_SUMMARY_KEY = env(
    "EXECUTIVE_SUMMARY_KEY",
    "PLACEHOLDER_REPLACE_WITH_YOUR_EXECUTIVE_SUMMARY_KEY",
)

LIVE_ENABLED = env_bool("LIVE_ENABLED", True)

# Minutes of inactivity before a signed-in session is ended automatically.
# Set to 0 to disable the idle timeout.
SESSION_IDLE_SECONDS = int(env("SESSION_IDLE_SECONDS", "300"))

LIVE_TIMEOUT = int(env("LIVE_TIMEOUT", "60"))

CACHE_TTL = int(env("CACHE_TTL", "120"))

SAMPLE_ASSESSMENT_ENABLED = env_bool("SAMPLE_ASSESSMENT_ENABLED", True)

APP_INSIGHTS_CONNECTION_STRING = env(
    "APP_INSIGHTS_CONNECTION_STRING",
    (
        "InstrumentationKey=d0289f46-5019-4176-856c-cd30b5dc2114;"
        "IngestionEndpoint=https://eastus-8.in.applicationinsights.azure.com/;"
        "LiveEndpoint=https://eastus.livediagnostics.monitor.azure.com/;"
        "ApplicationId=2eee2d29-508b-4621-a9ba-6f2ae6c6b5de"
    ),
)

APP_INSIGHTS_ENABLED = env_bool("APP_INSIGHTS_ENABLED", True)

# --- Optional SMTP for registration approval emails -----------------------
#
# When unset, approval emails are skipped (with a logged warning) and the
# pending approvals remain visible to administrators under Settings > Users.
SMTP_HOST = env("SMTP_HOST")
SMTP_PORT = int(env("SMTP_PORT", "587"))
SMTP_USER = env("SMTP_USER")
SMTP_PASSWORD = env("SMTP_PASSWORD")
SMTP_USE_TLS = env_bool("SMTP_USE_TLS", True)
MAIL_FROM = env(
    "MAIL_FROM",
    env("SMTP_FROM", "security-platform@ltm.local"),
)

# Comma-separated recipients for approval notifications. When empty, the
# platform notifies every account whose role is Admin/Administrator instead.
MAIL_APPROVAL_RECIPIENTS = env("MAIL_APPROVAL_RECIPIENTS")

APP_BASE_URL = env("APP_BASE_URL", "")
