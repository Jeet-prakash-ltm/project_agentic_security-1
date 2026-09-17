# LTM Security Platform — Project Structure

Agentic network & cloud security assessment platform. Four code units plus CI/CD:

| Unit | Technology | Purpose |
|------|------------|---------|
| `ui/` | Flask (Python 3.11) + PostgreSQL | Web console: landing, auth, Network Security dashboard, Cloud Security, System Info, AI Workspace, Investigation Centre, Reports, Agent Insights, Telemetry Map, Settings |
| `netsec-agent/` | Azure Functions (Python) | Palo Alto Networks firewall auditor (network security) |
| `cloudsec-agent/` | Azure Functions (Python) | Azure / Microsoft 365 cloud security & incident response |
| `netsec-execution-agent/` | Python package | Standalone source of the playbook-driven bulk PAN-OS change engine |
| `.github/` | GitHub Actions | CI/CD build + deploy of `ui/` to Azure App Service |

---

## 1. Repository Layout

```
project_agentic_security/
├── .github/
│   └── workflows/
│       └── master_ltm-security-platform-ui.yml   # Build & deploy ui/ -> Azure Web App
├── .gitignore
├── PROJECT_STRUCTURE.md                          # This document
│
├── ui/                              # Flask web console (PostgreSQL is the only store)
│   ├── app.py                       # Flask app: routes, auth guards, startup validation (~1.8k lines)
│   ├── requirements.txt             # flask, requests, gunicorn, SQLAlchemy, psycopg2-binary, openpyxl, PyYAML, reportlab
│   ├── config/
│   │   ├── settings.py              # All configuration from environment variables (no Key Vault)
│   │   ├── agents.json              # Agent seed registry (loaded into the agents table on boot)
│   │   └── *.json                   # Legacy seed/backup for assessment, insights, reports, sessions, users, telemetry
│   ├── database/                    # PostgreSQL persistence layer
│   │   ├── db.py                    # SQLAlchemy engine/session/Base + database URL resolution
│   │   ├── models.py                # ORM models (see table list in §3.5)
│   │   ├── startup.py               # Fail-fast startup validation + additive schema reconciliation
│   │   ├── schema_validation.py     # Schema drift detection and repair-SQL generation
│   │   ├── migrations/README.md     # Schema + migration guidance
│   │   └── repositories/
│   │       ├── base.py                            # Shared repository CRUD
│   │       ├── users_repository.py
│   │       ├── agents_repository.py
│   │       ├── conversations_repository.py
│   │       ├── findings_repository.py
│   │       ├── insights_repository.py
│   │       ├── reports_repository.py
│   │       ├── telemetry_repository.py
│   │       ├── assessments_repository.py
│   │       ├── demo_requests_repository.py
│   │       └── managed_firewalls_repository.py
│   ├── gateway/                     # Agent chat orchestration
│   │   ├── agent_gateway.py         # Chat orchestration entry point
│   │   ├── foundry_client.py        # Azure AI Foundry agent / responses client
│   │   ├── session_manager.py       # Conversation persistence backed by PostgreSQL
│   │   └── tools.py                 # Agent tool registry
│   ├── services/
│   │   ├── assessment_service.py        # Posture, findings, history; live functions or sample fallback
│   │   ├── dashboard_service.py         # Dashboard metrics + recent findings + history
│   │   ├── agents_service.py            # Agent registry backed by the `agents` table
│   │   ├── agent_status_service.py      # Per-agent liveness probe (Agent Health card)
│   │   ├── users_service.py             # Users, auth, roles, approval states
│   │   ├── insights_service.py          # Conversation/insight summarisation (`insights` table)
│   │   ├── report_history_service.py    # Report ledger (`reports_history` table)
│   │   ├── telemetry_map_service.py     # Telemetry map graph + metrics
│   │   ├── firewall_data_service.py     # Per-connector firewall data (live + fallback)
│   │   ├── firewall_bulk_service.py     # Bulk firewall inventory import (Settings > Asset Inventory)
│   │   ├── managed_firewalls_service.py # Managed firewall registry (`managed_firewalls` table)
│   │   ├── function_client.py           # Azure Function HTTP client + live fallback
│   │   ├── system_status_service.py     # Live/sample status
│   │   ├── sample_assessment.py         # Sample/fallback assessment data
│   │   ├── app_insights.py              # Application Insights telemetry
│   │   ├── chat_service.py              # Thin chat facade over gateway
│   │   ├── netsec_service.py            # NetSec Execution Agent workspace bridge
│   │   ├── foundry_incidents.py         # Deterministic Foundry routing for CloudSec actions
│   │   ├── demo_request_service.py      # Landing-page demo lead capture
│   │   ├── mailer.py                    # SMTP approval/demo notifications
│   │   ├── bootstrap.py                 # One-time admin/agent/legacy tenant bootstrap
│   │   └── timeutil.py
│   ├── scripts/
│   │   ├── migrate_json_to_postgres.py   # One-time JSON -> PostgreSQL migration
│   │   ├── sync_postgres_schema.py       # Apply schema reconciliation
│   │   ├── validate_schema.py            # Schema drift check
│   │   ├── validate_migration.py         # Post-migration verification
│   │   ├── test_db_connection.py         # DB connectivity check
│   │   └── azure_schema_sync.sql         # Additive DDL for Azure PostgreSQL
│   ├── static/
│   │   ├── css/                     # main, theme, dashboard, findings, insights, landing, login,
│   │   │                            #   reports, settings, system_info, telemetry_map, workspace
│   │   ├── js/                      # main, dashboard, findings, finding_enrichment, insights, landing,
│   │   │                            #   netsec, reports, settings, system_info, telemetry_map, workspace
│   │   ├── images/logo.svg
│   │   ├── LTM_LOGO.png             # Sidebar/favicon logo
│   │   ├── reports/                 # Generated PDF / XLSX artifacts
│   │   └── vendor/                  # cytoscape.min.js + webfonts
│   ├── netsec_execution/            # NetSec Execution Agent engine (deployed copy)
│   │   ├── connector/panos.py       # PAN-OS XML-API client (keygen + config get/set/delete, dry-run)
│   │   ├── playbooks/               # 11 YAML playbooks (NN- prefix sets catalogue order)
│   │   ├── services/                # catalog, common, engine, loader, network, objects, policies, workbook
│   │   └── run_playbook.py          # CLI runner
│   ├── templates/
│   │   ├── base.html                # Shell: collapsible sidebar, topbar, toast, global agent
│   │   ├── landing.html             # Public marketing page
│   │   ├── login.html               # Sign-in page (admin-created accounts only)
│   │   ├── dashboard.html           # Network Security posture dashboard (multi-firewall)
│   │   ├── cloud_security.html      # Cloud Security view
│   │   ├── system_info.html         # System Info view
│   │   ├── workspace.html           # AI Workspace (chat + conversation history + playbook panel)
│   │   ├── findings.html            # Investigation Centre / Security Operations
│   │   ├── telemetry_map.html
│   │   ├── insights.html
│   │   ├── reports.html
│   │   ├── settings.html
│   │   ├── accounts.html            # Settings > Accounts
│   │   ├── inventory.html           # Settings > Asset Inventory
│   │   ├── agents.html              # Settings > Agents
│   │   └── _settings_nav.html       # Shared settings sub-navigation partial
│   └── preview_*.html               # Local static preview renders (untracked build artifacts)
│
├── netsec-agent/                    # Palo Alto firewall auditor (Azure Functions)
│   ├── PROJECT_STRUCTURE.md         # Module-level structure doc
│   ├── test_inventory.py
│   └── functions/
│       ├── function_app.py          # HTTP-triggered endpoints (15 routes)
│       ├── host.json / local.settings.json / requirements.txt
│       ├── connectors/
│       │   ├── paloalto/            # Collectors: inventory, health, HA, policy, security services,
│       │   │                        #   routing, VPN, logging, administration, zone protection, backup
│       │   └── utils/xml_parser.py
│       ├── compliance/
│       │   ├── compliance_engine.py # Baseline evaluation
│       │   └── findings_generator.py# Finding generation
│       ├── baseline/
│       │   ├── PaloAlto_Compliance_Baseline.txt
│       │   └── baseline_rules.json
│       ├── reports/
│       │   ├── report_generator.py
│       │   ├── executive_summary.py / executive_summary_pdf.py
│       │   ├── risk_summary.py
│       │   ├── excel_report.py
│       │   └── timeutil.py
│       ├── dbwriter/persist.py      # Optional PostgreSQL persistence for the function app
│       ├── openapi/firewall-auditor-openapi.json
│       ├── PaloAlto_Assessment.xlsx
│       └── test_excel.py
│
├── cloudsec-agent/                  # Azure / M365 cloud security & incident response
│   ├── function_app.py              # IR tool endpoints (all POST triggers)
│   ├── host.json / local.settings.json / requirements.txt
│   ├── incident_response_schema.json
│   ├── cloudsec.zip                 # Deployment package
│   ├── connectors/
│   │   ├── auth.py
│   │   ├── network_connector.py
│   │   ├── sentinel_connector.py
│   │   └── vm_connector.py
│   └── services/
│       ├── common.py
│       ├── get_incidents_service.py / get_incident_service.py
│       ├── generate_summary_service.py
│       ├── get_vm_context_service.py / get_vm_instance_view_service.py
│       └── start_vm_service.py / stop_vm_service.py / restart_vm_service.py /
│           isolate_vm_service.py / reconnect_vm_service.py
│
└── netsec-execution-agent/          # Standalone source of ui/netsec_execution
    ├── README.md
    ├── connector/panos.py
    ├── playbooks/                   # 11 YAML playbooks
    ├── services/                    # catalog, common, engine, loader, network, objects, policies, workbook
    └── run_playbook.py
```

> `ui/netsec_execution/` is the deployed copy of the standalone
> `netsec-execution-agent/` package. Keep the two in sync before commit.

---

## 2. Architecture

```
+-------------------------------------------------------+
|                     Browser (Client)                   |
|  Landing -> Login -> Network Security -> Workspace ->  |
|  Investigation Centre -> Reports / Insights / Settings |
+-------------------------+-----------------------------+
                          | HTTP (Flask, port 8003)
                          v
+-------------------------------------------------------+
|                 Flask Web Console (ui/)                |
|  +-----------+  +------------+  +------------------+   |
|  | gateway/  |  | services/  |  | config/settings  |   |
|  | agent chat|  | assessment |  | env-driven       |   |
|  | sessions  |  | dashboard  |  +------------------+   |
|  | tools     |  | telemetry  |  | database/ (PG)   |   |
|  | foundry   |  | insights   |  | repositories     |   |
|  +-----+-----+  +-----+------+  +------------------+   |
+--------+---------------+-------------------------------+
         |               |
         |               v
         |      +-------------------+
         |      | Azure AI Foundry  |
         |      | (LLM agents)      |
         |      +-------------------+
         |
         | HTTP (function key auth)
         v
+--------+----------------------------------------------+
|   Azure Functions - netsec-agent (Palo Alto auditor)   |
|   get_inventory / get_health_status / get_ha_config    |
|   get_policy / security_services / routing / vpn /     |
|   logging / administration / zone_protection / backup  |
|   run_full_assessment / run_compliance_assessment      |
|   executive_summary / generate_excel_report            |
+-------------------------------------------------------+
|   Azure Functions - cloudsec-agent (Azure/M365 IR)     |
|   GetSentinelIncidents / GetSentinelIncident /         |
|   GenerateIncidentSummary / GetVMContext /             |
|   GetVMInstanceView / StartVM / StopVM / RestartVM /   |
|   IsolateAzureVM / RestoreVMConnectivity               |
+-------------------------------------------------------+

  PostgreSQL  <-- single source of truth for users, agents,
                  conversations, findings, insights, reports,
                  assessments, telemetry, managed firewalls
```

---

## 3. Flask Web Console (`ui/`)

Entry point `ui/app.py` (run with `python3 app.py`, host `0.0.0.0`, port `8003`,
`debug=True` locally).

### 3.1 Boot & persistence

PostgreSQL is the **only** supported storage layer. At import time
`run_startup_validation()` calls `database.startup.validate_runtime()`, which:

1. requires `DATABASE_URL`,
2. checks PostgreSQL reachability,
3. creates missing tables (`CREATE TABLE IF NOT EXISTS`),
4. adds missing columns/indexes (`ADD COLUMN IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`).

If the database is unavailable the process logs `FATAL: PostgreSQL unavailable`
and exits — there is **no JSON fallback**. The JSON files under `config/` are
legacy seed/backup data used by the one-time migration scripts.

### 3.2 Authentication & roles

- Sign-in is real (`users_service.authenticate`); self-registration is disabled.
- Accounts are created by administrators (Settings > Accounts) and may be
  `pending`, active, `rejected` or `disabled`.
- `login_required` guards app pages; `admin_required` guards `/api/admin/*`.
- Idle timeout is enforced from `SESSION_IDLE_SECONDS` (default 300s).
- Public routes: `/`, `/login`, `/logout`, `/request-demo`.

### 3.3 Page routes

| Route | Method | Template | Purpose |
|-------|--------|----------|---------|
| `/` | GET | `landing.html` | Public landing / marketing page |
| `/login` | GET/POST | `login.html` | Sign-in (admin-created accounts only) |
| `/logout` | GET | redirect | Clears session; returns to landing or login |
| `/request-demo` | POST | JSON | Landing demo lead capture + notification |
| `/dashboard` | GET | `dashboard.html` | Network Security posture dashboard |
| `/dashboard/cloud-security` | GET | `cloud_security.html` | Cloud Security view |
| `/dashboard/system-info` | GET | `system_info.html` | System Info view |
| `/workspace` | GET | `workspace.html` | AI Workspace (chat + history + playbook panel) |
| `/findings` | GET | `findings.html` | Investigation Centre / Security Operations |
| `/run-assessment` | GET | `findings.html` | Force a fresh assessment then render findings |
| `/reports` | GET | `reports.html` | Report history |
| `/executive-summary` | GET | PDF | Executive summary PDF (stores report history) |
| `/generate-excel` | GET | XLSX | Generate Excel workbook (stores report history) |
| `/download-workbook` | GET | file | Download generated workbook |
| `/insights` | GET | `insights.html` | Agent insights / Agent Health |
| `/telemetry-map` | GET | `telemetry_map.html` | Telemetry graph (nav entry disabled) |
| `/settings` | GET | `settings.html` | Settings landing |
| `/settings/accounts` | GET | `accounts.html` | User accounts (admin UI) |
| `/settings/inventory` | GET | `inventory.html` | Managed asset inventory (admin UI) |
| `/settings/agents` | GET | `agents.html` | Agent registry (admin UI) |

> `render_with_css()` auto-attaches the template's same-named CSS from
> `static/css/` as `page_css` when present. Settings pages are reachable by any
> signed-in user; management actions inside them are admin-only.

### 3.4 API routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/api/findings` | GET | Posture + findings |
| `/api/compliance` | GET | Full compliance assessment |
| `/api/firewall/inventory` | GET | Firewall inventory |
| `/api/firewall/health` | GET | Health status |
| `/api/firewall/ha` | GET | HA configuration |
| `/api/firewall/policy` | GET | Policy configuration |
| `/api/firewall/services` | GET | Security services |
| `/api/firewall/status` | GET | Connector status |
| `/api/firewall/routing` | GET | Routing configuration |
| `/api/firewall/vpn` | GET | VPN configuration |
| `/api/firewall/logging` | GET | Logging configuration |
| `/api/firewall/administration` | GET | Administration configuration |
| `/api/firewall/zone-protection` | GET | Zone protection configuration |
| `/api/firewall/backup` | GET | Backup configuration |
| `/api/firewall-inventory` | GET | Managed firewall inventory (from registry) |
| `/api/estate/assessment` | GET | Estate-wide assessment |
| `/api/estate/excel` | GET | Estate Excel report |
| `/api/summary` | GET | Aggregated summary |
| `/api/excel` | GET | Generate Excel report |
| `/api/agents` | GET/POST | List / add agents |
| `/api/agents/<agent_id>` | DELETE | Remove agent |
| `/api/agent-status` | GET | Per-agent liveness probe |
| `/api/chat` | POST | AI chat (single turn) |
| `/api/cloudsec/action` | POST | CloudSec incident / VM action |
| `/api/tools` | GET | Tool registry |
| `/api/conversations` | GET | List all conversations |
| `/api/conversations/<id>/messages` | GET/POST | Read / persist messages |
| `/api/conversations/<id>/clear` | POST | Clear a conversation |
| `/api/conversations/<id>/truncate` | POST | Truncate a conversation |
| `/api/me` | GET | Current user profile |
| `/api/insights` | GET | Insight summary |
| `/api/insights/conversation/<id>` | GET | Per-conversation summary |
| `/api/dashboard` | GET | Dashboard metrics + history + recent findings |
| `/api/reports` | GET | Report history |
| `/api/system-status` | GET | Live/sample status |
| `/api/telemetry-map` | GET | Telemetry graph |
| `/api/telemetry-map/history` | GET | Telemetry history |
| `/api/netsec/info` | GET | NetSec panel: connection status + playbook catalogue |
| `/api/netsec/workbook/template` | GET | Download fill-in playbook `.xlsx` template |
| `/api/netsec/workbook` | GET/POST | Read / store the user's playbook workbook |
| `/api/netsec/playbooks/run` | POST | Execute a playbook against the firewall (per-row) |
| `/api/netsec/manual` | POST | Run a manual (non-workbook) playbook action |
| `/api/admin/users` | GET/POST | List roster (scoped by role) / create user (admin) |
| `/api/admin/users/<user_id>/approve` | POST | Approve pending account (admin) |
| `/api/admin/users/<user_id>/reject` | POST | Reject pending account (admin) |
| `/api/admin/users/<user_id>/remove` | POST | Remove account (admin) |
| `/api/admin/users/<user_id>/role` | POST | Change role (admin) |
| `/api/admin/demo-requests` | GET | Landing demo leads (admin) |
| `/api/admin/firewalls` | GET/POST | List managed firewalls / add one (admin) |
| `/api/admin/firewalls/<int:firewall_id>` | DELETE | Remove managed firewall (admin) |
| `/api/admin/firewalls/<int:firewall_id>/clone` | POST | Clone managed firewall (admin) |
| `/api/admin/firewalls/template` | GET | Firewall import template (admin) |
| `/api/admin/firewalls/bulk` | POST | Bulk import managed firewalls (admin) |

### 3.5 PostgreSQL schema

Tables defined in `database/models.py` and required by `database/startup.py`:

| Table | Holds |
|-------|-------|
| `users` | Accounts, roles, approval state |
| `agents` | Registered agents / copilots |
| `conversations` + `messages` | AI Workspace sessions |
| `insights` | Conversation summaries / insight cards |
| `reports_history` | Report ledger |
| `assessment_history` | Assessment snapshots |
| `assessment_stats` | Assessment counters |
| `findings` | Normalised findings |
| `telemetry_metrics` / `telemetry_history` | Telemetry map data |
| `agent_activity_logs` | Agent activity logging |
| `demo_requests` | Landing-page leads |
| `managed_firewalls` | Managed firewall inventory |

### 3.6 NetSec Execution Agent engine (`ui/netsec_execution/`)

Playbook-driven bulk PAN-OS configuration:

- `connector/panos.py` — XML-API client (keygen + config get/set/delete, dry-run).
- `playbooks/*.yaml` — 11 playbooks: address objects/groups, services/groups,
  zones, virtual routers, static routes, management/interfaces, security rules,
  NAT rules.
- `services/` — `catalog`, `loader`, `engine`, `objects`, `network`, `policies`,
  `workbook`, `common`.
- `run_playbook.py` — CLI runner (`python -m netsec_execution.run_playbook`).

The UI exposes this as the "Firewall Execution Agent" in the workspace
(download -> fill -> upload -> run). Playbooks talk **directly** to the firewall
XML API from the web app; credentials are environment-only and are never stored
in the database.

---

## 4. Azure Functions — `netsec-agent/`

Palo Alto Networks firewall auditor. HTTP triggers in `functions/function_app.py`:

- `get_inventory`, `get_health_status`, `get_ha_configuration`
- `get_policy_configuration`, `get_security_services`, `get_routing_configuration`
- `get_vpn_configuration`, `get_logging_configuration`, `get_administration_configuration`
- `get_zone_protection_configuration`, `get_backup_configuration`
- `run_full_assessment`, `run_compliance_assessment`
- `executive_summary`, `generate_excel_report`

Supporting modules: `connectors/paloalto/*` (device collectors),
`connectors/utils/xml_parser.py`, `compliance/*` (baseline evaluation + finding
generation), `baseline/*` (rules), `reports/*` (summary / risk / Excel / PDF),
and `dbwriter/persist.py` (optional PostgreSQL persistence).

---

## 5. Azure Functions — `cloudsec-agent/`

Azure / Microsoft 365 cloud security and incident response toolset
(`function_app.py`), all POST triggers:

- Detection: `GetSentinelIncidents`, `GetSentinelIncident`, `GenerateIncidentSummary`
- Compute: `GetVMContext`, `GetVMInstanceView`
- Response: `StartVM`, `StopVM`, `RestartVM`, `IsolateAzureVM`, `RestoreVMConnectivity`

---

## 6. Configuration (`ui/config/settings.py`)

All configuration is read **directly from environment variables** (Azure App
Service > Configuration > Application Settings; locally from the environment or
`.env`). There is no Azure Key Vault integration and no `config/storage.py`.

| Variable | Purpose | Default |
|----------|---------|---------|
| `SECRET_KEY` | Flask session signing key | dev-only placeholder |
| `DATABASE_URL` | PostgreSQL connection string (required at startup) | none |
| `FIREWALL_FUNCTION_URL` (alias `BASE_URL`) | netsec-agent function base URL | baked-in function URL |
| `FIREWALL_FUNCTION_KEY` | Key for single-control function endpoints | placeholder |
| `FULL_ASSESSMENT_KEY` | Key for `run_full_assessment` | placeholder |
| `EXCEL_KEY` | Key for `generate_excel_report` | placeholder |
| `EXECUTIVE_SUMMARY_KEY` | Key for `executive_summary` | placeholder |
| `LIVE_ENABLED` | Toggle live function calls | `true` |
| `LIVE_TIMEOUT` | Live call timeout (seconds) | `60` |
| `CACHE_TTL` | Assessment cache TTL (seconds) | `120` |
| `SESSION_IDLE_SECONDS` | Inactivity sign-out (0 disables) | `300` |
| `SAMPLE_ASSESSMENT_ENABLED` | Enable sample/fallback data | `true` |
| `APP_INSIGHTS_CONNECTION_STRING` | Application Insights ingestion | baked-in |
| `APP_INSIGHTS_ENABLED` | Toggle App Insights telemetry | `true` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_USE_TLS` | Approval/demo e-mail | unset |
| `MAIL_FROM` (alias `SMTP_FROM`) | Sender address | `security-platform@ltm.local` |
| `MAIL_APPROVAL_RECIPIENTS` | Approval notification recipients | all admins |
| `APP_BASE_URL` | Absolute base URL used in e-mails | request host |
| `NETSEC_FW_HOST` | Firewall host/IP targeted by playbooks | — |
| `NETSEC_FW_USERNAME` / `NETSEC_FW_PASSWORD` | Admin credentials for `keygen` | — |
| `NETSEC_FW_API_KEY` | Pre-generated API key (skips `keygen`) | — |
| `NETSEC_FW_DRY_RUN` | `1` previews changes, `0` applies **and commits** | `1` |
| `NETSEC_WORKBOOK_DIR` | Where uploaded workbooks are stored | `/tmp/netsec_uploads` |
| `NETSEC_MAX_ROWS` | Max data rows executed per run | `500` |

---

## 7. Deployment

### 7.1 UI — Azure Web App (`ui/`)

Deployed via GitHub Actions
(`.github/workflows/master_ltm-security-platform-ui.yml`):

- **Trigger**: `push` to `master` or `workflow_dispatch`.
- **Build job**: checkout -> setup-python 3.11 -> create venv `antenv` in `./ui`
  -> `pip install -r requirements.txt` -> upload `ui/` as artifact `python-app`.
- **Deploy job**: `azure/webapps-deploy@v3` -> app `ltm-security-platform-ui`,
  slot `Production`, using the publish-profile secret.
- **Live URL**: `https://ltm-security-platform-ui-c8fff7f9ghb0e6hg.southindia-01.azurewebsites.net`
- **Local run**: `cd ui && python3 app.py` (port `8003`).

### 7.2 Azure Functions — `netsec-agent/` & `cloudsec-agent/`

Deployed as Azure Function Apps (zip-deploy). Function-key auth is used by the
UI (`services/function_client.py`) for live firewall calls; when keys are absent
the UI degrades to sample data or the assessment snapshot.

### 7.3 Secrets (never committed)

- GitHub Actions publish-profile secret (`AZUREAPPSERVICE_PUBLISHPROFILE_...`).
- App Service application settings: `DATABASE_URL`, function keys, Foundry keys,
  App Insights connection string, `NETSEC_FW_*`, SMTP credentials.
- `ui/config/agents.json` — agent API keys are placeholders; live keys are
  supplied through environment/app settings.
