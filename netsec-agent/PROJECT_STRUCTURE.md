# netsec-agent — Project Structure & Integration

Palo Alto Networks firewall auditor and the network-security half of the LTM
Security Platform. This document covers the `netsec-agent/` Azure Functions
app and how the Flask web console (`ui/`) consumes it. For the full platform
layout see the repository-root `PROJECT_STRUCTURE.md`.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Directory Map](#directory-map)
3. [Azure Functions Backend (`functions/`)](#azure-functions-backend-functions)
4. [Flask UI Integration (`ui/`)](#flask-ui-integration-ui)
5. [Data Flow](#data-flow)
6. [Design Patterns](#design-patterns)
7. [Configuration & Persistence](#configuration--persistence)

---

## Architecture Overview

```
+-------------------------------------------------------+
|                     Browser (Client)                   |
|  Network Security | Cloud Security | System Info |     |
|  AI Workspace | Investigation Centre | Reports |       |
|  Agent Insights | Telemetry Map | Settings             |
+-------------------------+-----------------------------+
                          |
                          | HTTP (Flask, port 8003)
                          v
+-------------------------+-----------------------------+
|             Flask Frontend (ui/app.py)                 |
|  +-----------+ +-------------+ +------------------+    |
|  |  gateway/ | |  services/  | | config/settings  |    |
|  |  (agent   | | (assessment | | (env-driven,     |    |
|  |   chat,   | |  dashboard, | |  no Key Vault)   |    |
|  |   session | |  insights,  | +------------------+    |
|  |   manager,| |  telemetry, | | database/ (PG)   |    |
|  |   tools,  | |  netsec)    | | repositories     |    |
|  |   foundry)| |             | |                  |    |
|  +-----+-----+ +------+------+ +------------------+    |
+--------+---------------+-------------------------------+
         |               |
         |               v
         |      +-----------------------+
         |      | Azure AI Foundry      |
         |      | (LLM chat backend)    |
         |      +-----------------------+
         |
         | HTTP (function-key auth)
         v
+--------+----------------------------------------------+
|       Azure Functions Backend (functions/)             |
|  +-------------+ +-------------+ +--------------+      |
|  | connectors/ | | compliance/ | |  reports/    |      |
|  | (paloalto   | | (engine +   | | (summary,    |      |
|  |  collector  | |  findings)  | |  pdf, excel, |      |
|  |  modules)   | |             | |  risk)       |      |
|  +------+------+ +------+------+ +------+-------+      |
|         |               |               |              |
|         v               v               v              |
|   +---------+    +-----------+    +---------+          |
|   | Palo    |    | Baseline  |    | .xlsx / |          |
|   | Alto    |    | Rules     |    | .pdf    |          |
|   | Firewall|    | (44 rules)|    | Reports |          |
|   +---------+    +-----------+    +---------+          |
|         |                                              |
|         v                                              |
|   dbwriter/persist.py  ---> PostgreSQL (optional)      |
+--------------------------------------------------------+
```

The platform separates two components:

| Component | Location | Runtime | Port | Purpose |
|-----------|----------|---------|------|---------|
| **Functions** | `netsec-agent/functions/` | Azure Functions (Python 3.11) | — | Connects to Palo Alto firewalls, collects config & health data, evaluates compliance, generates findings and reports |
| **UI** | repo-root `ui/` | Flask (Python 3.11) | 8003 | Web console: dashboards, AI chat, investigation centre, reports, insights, telemetry, settings |

---

## Directory Map

```
netsec-agent/
├── PROJECT_STRUCTURE.md            # This document
├── test_inventory.py               # Quick test: connect to a firewall and print inventory
│
└── functions/                      === AZURE FUNCTIONS BACKEND ===
    ├── function_app.py             Main entry: 15 HTTP routes (function-key auth)
    ├── host.json                   Azure Functions host config (v2)
    ├── local.settings.json         Local dev settings
    ├── requirements.txt            azure-functions, requests, pan-os-python, openpyxl, psycopg2-binary
    ├── test_excel.py               ExcelReport smoke test
    ├── PaloAlto_Assessment.xlsx    Sample assessment workbook output
    │
    ├── baseline/
    │   ├── baseline_rules.json               44 compliance rules (PA-01 … PA-67)
    │   └── PaloAlto_Compliance_Baseline.txt  Human-readable compliance reference
    │
    ├── compliance/
    │   ├── compliance_engine.py    ComplianceEngine: evaluates assessment data against baseline rules
    │   └── findings_generator.py   FindingsGenerator: turns non-compliant results into findings + remediation
    │
    ├── connectors/
    │   ├── utils/
    │   │   └── xml_parser.py       XMLParser: get_root/get_text/get_int/get_float/get_elements…
    │   └── paloalto/              === 11 collector modules ===
    │       ├── paloalto_connector.py          Facade orchestrating all collectors
    │       ├── inventory.py                   Device info (hostname, model, version)
    │       ├── health_status.py               CPU, memory, disk, session utilization
    │       ├── ha_configuration.py            HA state, peer status, sync monitoring
    │       ├── policy_configuration.py        Security rules, NAT, zones, App-ID %
    │       ├── security_services.py           Threat/AV/AS/DNS/WildFire/URL/SSL
    │       ├── routing_configuration.py       Virtual routers, BGP, OSPF
    │       ├── vpn_configuration.py           GlobalProtect, IKE, IPsec, MFA
    │       ├── logging_configuration.py       Syslog, SIEM, SNMP, profiles
    │       ├── administration_configuration.py Admins, management IPs, HTTPS, NTP
    │       ├── zone_protection_configuration.py Zone/DoS profiles
    │       └── backup_configuration.py        Scheduled backup jobs
    │
    ├── reports/
    │   ├── report_generator.py     ReportGenerator: thin wrapper delegating to summaries
    │   ├── executive_summary.py    ExecutiveSummary: management-level summary text
    │   ├── executive_summary_pdf.py PDF rendering of the executive summary
    │   ├── excel_report.py         ExcelReport: multi-sheet workbook (openpyxl)
    │   ├── risk_summary.py         RiskSummary: CRITICAL/HIGH/MEDIUM/LOW risk level
    │   └── timeutil.py
    │
    ├── dbwriter/
    │   └── persist.py              Optional PostgreSQL persistence (agent_activity_logs,
    │                               assessments, findings) for the function app
    │
    └── openapi/
        └── firewall-auditor-openapi.json   OpenAPI 3.0.1 spec (15 endpoints)
```

---

## Azure Functions Backend (`functions/`)

**Entry point:** `function_app.py` — a Flask `FunctionApp` exposing 15 HTTP
routes, all with `AuthLevel.FUNCTION`.

| Route | Method | Purpose |
|-------|--------|---------|
| `get_inventory` | GET | Device info (hostname, model, serial, version) |
| `get_health_status` | GET | CPU, memory, disk, session utilization |
| `get_ha_configuration` | GET | HA state, peer status, sync monitoring |
| `get_policy_configuration` | GET | Security rules, NAT, zones, App-ID analysis |
| `get_security_services` | GET | Threat/AV/AS/DNS/WildFire/URL/SSL config |
| `get_routing_configuration` | GET | Virtual routers, static routes, BGP/OSPF |
| `get_vpn_configuration` | GET | GlobalProtect, IKE, IPsec, MFA |
| `get_logging_configuration` | GET | Syslog, SIEM, SNMP, profiles |
| `get_administration_configuration` | GET | Admins, management IPs, HTTPS/SSH, NTP |
| `get_zone_protection_configuration` | GET | Zone protection, DoS profiles |
| `get_backup_configuration` | GET | Scheduled backup jobs |
| `run_full_assessment` | GET | Runs all 11 collectors, returns full JSON |
| `run_compliance_assessment` | GET | Full assessment -> compliance evaluation -> findings |
| `executive_summary` | GET | Management-level summary text |
| `generate_excel_report` | GET | Multi-sheet `.xlsx` workbook |

`run_full_assessment` and `run_compliance_assessment` additionally log an
`agent_activity_logs` row and call `dbwriter.persist_assessment(...)` when a
database is reachable.

**Connector architecture:** `PaloAltoConnector` in `paloalto_connector.py` is a
Facade wrapping 11 collector modules. Each collector:

1. Connects to the firewall via the PAN-OS XML API (`pan-os-python`).
2. Runs XML API commands (`show system info`, `show session info`, …).
3. Parses responses with the `XMLParser` utility.
4. Returns structured Python dicts.

`get_connector()` builds the connector per request and delegates to the
appropriate collector.

**Compliance pipeline:**

```
Assessment JSON -> ComplianceEngine.evaluate() -> 44-rule baseline ->
COMPLIANT / NON_COMPLIANT / NOT_ASSESSED ->
FindingsGenerator.generate() -> remediation-guided findings
```

**Reports pipeline:**

```
Assessment JSON -> ExecutiveSummary.generate() -> text/PDF summary
Assessment JSON -> ExcelReport.generate()      -> multi-sheet .xlsx workbook
Findings JSON   -> RiskSummary.calculate()     -> CRITICAL/HIGH/MEDIUM/LOW
```

---

## Flask UI Integration (`ui/`)

The console consumes the auditor through `services/function_client.py`
(function-key auth, live-first with sample fallback). `firewall_data_service.py`
exposes the per-connector payloads. Key page/API routes for network security:

**Pages** (all `@login_required`):

| Route | Template | Description |
|-------|----------|-------------|
| `/dashboard` | `dashboard.html` | Network Security posture dashboard (multi-firewall) |
| `/dashboard/cloud-security` | `cloud_security.html` | Cloud Security view |
| `/dashboard/system-info` | `system_info.html` | System Info view |
| `/findings` | `findings.html` | Investigation Centre |
| `/run-assessment` | `findings.html` | Force a fresh assessment, then render findings |
| `/reports` | `reports.html` | Report history |
| `/insights` | `insights.html` | Agent insights / Agent Health |

**API** (subset):

| Route | Method | Service | Returns |
|-------|--------|---------|---------|
| `/api/compliance` | GET | `assessment_service` | Compliance results + findings |
| `/api/findings` | GET | `assessment_service` | Posture + findings |
| `/api/firewall/*` | GET | `firewall_data_service` | inventory, health, ha, policy, services, status, routing, vpn, logging, administration, zone-protection, backup |
| `/api/firewall-inventory` | GET | `managed_firewalls_service` | Managed firewall registry |
| `/api/estate/assessment` | GET | `assessment_service` | Estate-wide assessment |
| `/api/summary` | GET | `assessment_service` | Aggregated summary |
| `/api/excel` | GET | `assessment_service` | `.xlsx` file download |
| `/api/dashboard` | GET | `dashboard_service` | Aggregated KPIs + history |
| `/api/reports` | GET | `report_history_service` | Report history |
| `/api/system-status` | GET | `system_status_service` | Component health |
| `/api/chat` | POST | `chat_service` | LLM chat response |
| `/api/conversations*` | GET/POST | `session_manager` | Conversation read/write |

See the repository-root `PROJECT_STRUCTURE.md` for the complete route and table
reference.

**Chat orchestration flow:**

```
Browser -> POST /api/chat -> ChatService -> AgentGateway
  ├── SessionManager  — load/save conversation (PostgreSQL)
  ├── FoundryClient   — POST to Azure AI Foundry endpoint
  ├── InsightsService — record token usage, latency, cost
  └── AppInsights     — send telemetry events
-> JSON response back to browser
```

**Assessment flow:**

```
Browser -> GET /api/compliance -> AssessmentService
  ├── Try: FunctionClient -> Azure Functions /run_compliance_assessment
  ├── Catch: fall back to SampleAssessment static data
  └── Cache for CACHE_TTL (120s)
-> JSON response with compliance results + findings
```

**System status probe** (`system_status_service.py`, 30s cache) reports 7
components: `agent`, `functions`, `firewall`, `foundry`, `model`,
`appinsights`, `gateway` -> overall `operational` / `degraded` / `offline`.

---

## Data Flow

### 1. Firewall Assessment (real-time)

```
Browser                Flask UI              Azure Functions           Palo Alto FW
  |                      |                        |                        |
  |--GET /api/compliance->|                        |                        |
  |                      |--GET /run_compliance-->|                        |
  |                      |                        |--XML API commands----->|
  |                      |                        |<--device config/data---|
  |                      |                        |--run 44 rules--------->|
  |                      |                        |--generate findings---->|
  |                      |<--JSON results----------|                        |
  |<--JSON response-------|                        |                        |
```

### 2. AI Chat (Agent Gateway)

```
Browser                Flask UI            Gateway           Azure AI Foundry
  |                      |                   |                     |
  |--POST /api/chat----->|                   |                     |
  |                      |--delegate-------->|                     |
  |                      |                   |--load session------>| (PostgreSQL)
  |                      |                   |--POST chat--------->|
  |                      |                   |<--LLM response------|
  |                      |                   |--save session------>|
  |                      |                   |--record insights--->|
  |                      |                   |--send telemetry--->|
  |                      |<--response---------|                     |
  |<--JSON response-------|                   |                     |
```

### 3. Telemetry Map Construction

```
Browser                Flask UI              TelemetryMapService
  |                      |                        |
  |--GET /api/telemetry->|                        |
  |                      |--build_map()----------->|
  |                      |                        |--query telemetry metrics
  |                      |                        |--resolve system status
  |                      |                        |--build node/edge graph
  |                      |                        |--compute health scores
  |                      |                        |--save history snapshot
  |                      |<--JSON graph------------|
  |<--JSON response-------|                        |
  |--render Cytoscape.js->|                        |
```

---

## Design Patterns

| Pattern | Where Used | Description |
|---------|-----------|-------------|
| **Facade** | `paloalto_connector.py` | Single entry point wrapping 11 collector modules |
| **Strategy** | `assessment_service.py`, `system_status_service.py` | Live -> sample fallback; probe with timeout |
| **Gateway** | `gateway/agent_gateway.py` | Centralised chat routing with session/insight/telemetry hooks |
| **Repository** | `database/repositories/*` | PostgreSQL-backed persistence per entity |
| **Cache-Aside** | `assessment_service.py` (120s), `system_status_service.py` (30s), `agents_service`, `firewall_data_service` | Avoid redundant calls |
| **Observer** | `insights_service.py` -> `app_insights.py` | Cost/token events forwarded to Azure telemetry |
| **Singleton** | `config/settings.py`, `database/db.py` engine | One settings object / engine per process |
| **Template Method** | `base.html` -> page templates | Shared layout with per-page blocks |

---

## Configuration & Persistence

Configuration is read **directly from environment variables** (Azure App Service
> Configuration > Application Settings). There is no `config/keyvault.py` and no
Key Vault dependency.

**UI settings** (`ui/config/settings.py`): `SECRET_KEY`, `DATABASE_URL`,
`FIREWALL_FUNCTION_URL`/`BASE_URL`, `FIREWALL_FUNCTION_KEY`,
`FULL_ASSESSMENT_KEY`, `EXCEL_KEY`, `EXECUTIVE_SUMMARY_KEY`, `LIVE_ENABLED`,
`LIVE_TIMEOUT`, `CACHE_TTL`, `SESSION_IDLE_SECONDS`,
`SAMPLE_ASSESSMENT_ENABLED`, `APP_INSIGHTS_CONNECTION_STRING`,
`APP_INSIGHTS_ENABLED`, SMTP/`MAIL_*`, `APP_BASE_URL`, and `NETSEC_FW_*`.

**Function app settings**: `PA_FIREWALL_HOST` (default `10.1.0.5`),
`PA_USERNAME` (default `fwadmin`), `PA_PASSWORD`, plus optional `DATABASE_URL`
and `DB_PERSIST_ASSESSMENTS` for `dbwriter/persist.py`, and standard Azure
Functions storage settings.

**Persistence**: PostgreSQL is the platform's single store. The JSON files under
`ui/config/` are legacy seed/backup data used only by the one-time migration
scripts (`ui/scripts/migrate_json_to_postgres.py`). The Function app writes to
PostgreSQL only when `DATABASE_URL` is present; otherwise it operates statelessly.
