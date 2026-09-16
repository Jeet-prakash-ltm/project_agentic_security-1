import os
import time

from functools import wraps

from flask import Flask
from flask import render_template
from flask import jsonify
from flask import url_for
from flask import request
from flask import redirect
from flask import send_file
from flask import session
from flask import g

from config import settings as platform_settings
from services import assessment_service
from services import agent_status_service
from services import agents_service
from services import dashboard_service
from services import demo_request_service
from services import insights_service
from services import mailer
from services import managed_firewalls_service
from services import report_history_service
from services import system_status_service
from services import telemetry_map_service
from services import firewall_data_service
from services import firewall_bulk_service
from services import foundry_incidents
from services import timeutil
from services import users_service
from gateway.agent_gateway import gateway
from gateway import session_manager

app = Flask(__name__)
app.secret_key = platform_settings.SECRET_KEY


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = users_service.get_user(user_id)
    if not user or (user.status or "approved") != "approved":
        session.pop("user_id", None)
        return None
    return users_service.public_user(user_id)


def current_user_id():
    return session.get("user_id") or "anonymous"


@app.before_request
def require_authentication():
    g.user = current_user()
    return _enforce_idle_timeout()


@app.context_processor
def inject_current_user():
    user = getattr(g, "user", None) or current_user()
    return {"current_user": user, "is_admin": _is_admin(user)}


def _is_admin(user):
    return bool(
        user
        and users_service.is_admin_role(user.get("role"))
    )


def _login_redirect():
    from urllib.parse import urlencode

    target = url_for("login")
    if request.endpoint:
        args = dict(request.view_args or {})
        args.update(request.args.to_dict())
        next_url = url_for(request.endpoint, **args) if request.endpoint != "login" else ""
        if next_url:
            target = url_for("login") + "?" + urlencode({"next": next_url})
    return redirect(target)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return _login_redirect()
        return f(*args, **kwargs)
    return wrapper


# --------------------------------------------------
# INACTIVITY TIMEOUT
# --------------------------------------------------

SESSION_IDLE_LIMIT = platform_settings.SESSION_IDLE_SECONDS


def _wants_json_response():
    """True for XHR/fetch/API calls that expect JSON rather than a page."""
    if request.path.startswith("/api/"):
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


def _expired_login_redirect(resume_url=""):
    """Send an idle user to the sign-in page, remembering where to resume."""
    from urllib.parse import urlencode

    query = {"expired": "1"}
    if resume_url:
        query["next"] = resume_url
    return redirect(url_for("login") + "?" + urlencode(query))


def _last_visited_page():
    """Best-effort URL of the page the browser is currently on."""
    if request.method == "GET" and not _wants_json_response():
        if request.query_string:
            return request.full_path.rstrip("?")
        return request.path
    return ""


def _enforce_idle_timeout():
    """End a signed-in session after a period of inactivity.

    Returns a redirect/response when the session has expired, otherwise
    ``None`` so the request proceeds normally.
    """
    if SESSION_IDLE_LIMIT <= 0 or not session.get("user_id"):
        return None
    if request.endpoint in (None, "static", "login", "logout"):
        return None

    now = time.time()
    try:
        last_seen = float(session.get("last_activity") or 0)
    except (TypeError, ValueError):
        last_seen = 0.0

    if last_seen and (now - last_seen) > SESSION_IDLE_LIMIT:
        resume_url = session.get("last_page") or _last_visited_page()
        session.clear()
        g.user = None
        if _wants_json_response():
            return jsonify({"error": "session_expired"}), 401
        return _expired_login_redirect(resume_url)

    session["last_activity"] = now
    page = _last_visited_page()
    if page:
        session["last_page"] = page
    return None


def _admin_or_403():
    """Return a (jsonify, status) tuple when the caller is not an admin."""
    user = current_user()
    if _is_admin(user):
        return None
    return jsonify({"error": "Administrator access required."}), 403


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        denied = _admin_or_403()
        if denied:
            return denied
        return f(*args, **kwargs)
    return wrapper


# --------------------------------------------------
# AUTO CSS LOADER
# --------------------------------------------------

def render_with_css(template_name, **context):

    css_filename = (
        os.path.splitext(template_name)[0]
        + ".css"
    )

    css_path = os.path.join(
        app.static_folder,
        "css",
        css_filename
    )

    if os.path.exists(css_path):
        context["page_css"] = css_filename
    else:
        context["page_css"] = None

    return render_template(
        template_name,
        **context
    )

# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def _is_managed_device(name):
    """True when ``name`` is registered in the managed firewall inventory."""
    name = (name or "").strip()
    if not name:
        return False
    try:
        return any(
            entry["device_name"] == name
            for entry in managed_firewalls_service.list_firewalls()
        )
    except Exception:
        return False


def _firewall_param():
    """Read the selected firewall from the query string (validated).

    Accepts a known logical firewall (``FIREWALLS``) or any device registered
    in the managed firewall inventory; falls back to ``vmpafw01``.
    """
    fw = (request.args.get("firewall") or "").strip()
    if fw in assessment_service.FIREWALLS or _is_managed_device(fw):
        return fw
    return "vmpafw01"


def _dashboard_firewall_param():
    """Dashboard selection: a managed device, or ``all`` for full inventory."""
    fw = (request.args.get("firewall") or "").strip()
    if fw.lower() in ("all", "estate", "full", "full inventory"):
        return "all"
    if not fw or fw in assessment_service.FIREWALLS:
        return fw or "vmpafw01"
    if _is_managed_device(fw):
        return fw
    return "vmpafw01"


def _relabel_firewall(data, firewall_id):
    """Relabel the firewall hostname to the selected logical name."""
    if isinstance(data, dict):
        if "hostname" in data:
            data["hostname"] = firewall_id
        inventory = data.get("inventory")
        if isinstance(inventory, dict) and "hostname" in inventory:
            inventory["hostname"] = firewall_id
    return data


def file_size_label(path):
    try:
        size_bytes = (
            os.path.getsize(path)
            if path and os.path.exists(path)
            else 0
        )
    except Exception:
        return "—"
    if not size_bytes:
        return "—"
    if size_bytes >= 1024 * 1024:
        return "{0:.2f} MB".format(size_bytes / (1024 * 1024))
    return "{0:.0f} KB".format(size_bytes / 1024)


def format_report_ts(ts):
    try:
        return timeutil.format_ist(ts)
    except (TypeError, ValueError, OverflowError):
        return "—"


app.add_template_filter(format_report_ts, "report_ts")


def initials(name):
    parts = (name or "").strip().split()
    letters = "".join(p[0] for p in parts if p).upper()
    return letters[:2] or "U"


app.add_template_filter(initials, "initials")


def render_reports(**context):
    context["reports"] = report_history_service.list_reports(
        user_id=current_user_id()
    )
    context["firewalls"] = assessment_service.FIREWALLS
    context.setdefault("firewall_id", _firewall_param())
    return render_with_css("reports.html", **context)

# --------------------------------------------------
# AUTH ROUTES (login / signup / logout)
# --------------------------------------------------

def _login_notice():
    if (request.args.get("expired") or "").strip().lower() in ("1", "true", "yes"):
        return "Your session was signed out after a period of inactivity. Please sign in again."
    notice = (request.args.get("notice") or "").strip()
    if not notice:
        return None
    return {
        "pending": (
            "Your account was created and is awaiting administrator "
            "approval. You will be able to sign in once it is approved."
        ),
        "logged_out": "You have been signed out.",
        "approved": "Your account has been approved. You can sign in now.",
        "rejected": "Your account request was declined. Contact an administrator.",
    }.get(notice)


@app.route("/login", methods=["GET", "POST"], endpoint="login")
def login():
    # Self-registration is disabled: accounts are created by administrators
    # from Settings > User Accounts. The sign-in page only signs in approved
    # users (a legacy ?mode=signup link is treated as plain sign-in).
    mode = "login"
    explicit_mode = (request.args.get("mode") or "").strip() in ("login", "signup")
    next_url = (request.args.get("next") or "").strip()
    if next_url and not (next_url.startswith("/") and not next_url.startswith("//")):
        next_url = ""

    if request.method == "POST":
        # Real authentication: only approved accounts may sign in. There is no
        # demo/any-credentials backdoor anymore.
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = users_service.authenticate(email, password)
        if user:
            session.clear()
            session["user_id"] = user["id"]
            session["last_activity"] = time.time()
            if next_url:
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        state = users_service.status_for_email(email)
        if state == "pending":
            error = (
                "Your account is pending approval. You will be able to sign "
                "in once an administrator approves it."
            )
        elif state in ("rejected", "disabled"):
            error = (
                "Your account is not active. Contact an administrator for "
                "assistance."
            )
        else:
            error = "Invalid email or password."
        return render_template(
            "login.html",
            mode=mode,
            error=error,
            notice=None,
            next_url=next_url,
            signup_roles=users_service.SIGNUP_ROLES,
        )

    # Already signed in? A plain visit to /login goes straight to the
    # dashboard, but when the user explicitly asked for the sign-in or
    # create-account page (landing page CTA with ?mode=) we still render the
    # auth page and surface the active session instead of silently skipping it.
    authenticated = current_user()
    if authenticated and not explicit_mode:
        return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        mode=mode,
        error=None,
        notice=_login_notice(),
        next_url=next_url,
        signup_roles=users_service.SIGNUP_ROLES,
        authenticated_user=authenticated,
    )


@app.route("/logout")
def logout():
    from urllib.parse import urlencode

    next_url = (request.args.get("next") or "").strip()
    if next_url and not (next_url.startswith("/") and not next_url.startswith("//")):
        next_url = ""
    expired = (request.args.get("expired") or "").strip().lower() in ("1", "true", "yes")

    session.clear()

    # Inactivity sign-out (and any logout that carries a target) returns to the
    # sign-in page remembering where to resume; an explicit sign-out from the
    # sidebar keeps the original "back to the landing page" behaviour.
    if expired or next_url:
        query = {}
        if expired:
            query["expired"] = "1"
        if next_url:
            query["next"] = next_url
        target = url_for("login")
        if query:
            target = target + "?" + urlencode(query)
        return redirect(target)

    return redirect(url_for("home"))


# --------------------------------------------------
# HOME (AI Workspace is the primary landing page)
# --------------------------------------------------

@app.route("/")
def home():

    return render_with_css(
        "landing.html"
    )


@app.route("/request-demo", methods=["POST"])
def request_demo():

    payload = request.get_json(silent=True) or {}
    try:
        lead = demo_request_service.create_lead(
            (payload.get("name") or "").strip(),
            (payload.get("email") or "").strip(),
            (payload.get("company") or "").strip(),
            (payload.get("role") or "").strip(),
            (payload.get("message") or "").strip(),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    delivery = mailer.send_demo_notification(
        lead,
        base_url=platform_settings.APP_BASE_URL or request.host_url,
    )
    if not delivery.get("delivered"):
        app.logger.info(
            "Demo request e-mail not sent for %s: %s",
            lead.get("email"),
            delivery.get("reason"),
        )

    return jsonify({"ok": True, "id": lead.get("id")}), 201

# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    """Network Security view (the default page after sign-in)."""

    connected = agents_service.get_connected_agent()

    return render_with_css(
        "dashboard.html",

        total_controls="-",
        compliant="-",
        non_compliant="-",
        not_assessed="-",
        base_model=(connected or {}).get("model", "gpt-5.1"),
        firewalls=assessment_service.FIREWALLS,
        firewall_id=_dashboard_firewall_param()
    )


@app.route("/dashboard/cloud-security")
@login_required
def cloud_security():
    """Cloud Security view under Dashboard (placeholder for now)."""

    return render_with_css(
        "cloud_security.html"
    )


@app.route("/dashboard/system-info")
@login_required
def system_info():
    """System Info view under Dashboard (placeholder for now)."""

    return render_with_css(
        "system_info.html"
    )

# --------------------------------------------------
# WORKSPACE
# --------------------------------------------------

@app.route("/workspace")
@login_required
def workspace():

    return render_with_css(
        "workspace.html"
    )

# --------------------------------------------------
# FINDINGS
# --------------------------------------------------

@app.route("/findings")
@login_required
def findings():

    return render_with_css(
        "findings.html",
        firewall_id=_firewall_param()
    )

# --------------------------------------------------
# RUN ASSESSMENT
# --------------------------------------------------

@app.route("/run-assessment")
@login_required
def run_assessment():

    try:

        data = (
            assessment_service
            .get_full_assessment(
                firewall_id=_firewall_param(),
                force=True,
                require_reachable=True,
            )
        )

        return render_with_css(
            "findings.html",

            assessment_source=(
                data.get("_source", "live")
            ),
            firewall_id=_firewall_param()
        )

    except assessment_service.AssessmentUnavailableError as e:

        # Firewall is down (e.g. the VM is stopped): tell the user clearly and
        # render a lightweight page that does not keep polling for findings.
        return render_with_css(
            "findings.html",

            assessment_blocked=True,
            firewall_name=_firewall_param(),
            error=str(e),
        )

    except Exception as e:

        return render_with_css(
            "findings.html",

            error=str(e)
        )

# --------------------------------------------------
# REPORTS
# --------------------------------------------------

@app.route("/reports")
@login_required
def reports():

    return render_reports()


# --------------------------------------------------
# EXECUTIVE SUMMARY
# --------------------------------------------------

@app.route("/executive-summary")
@login_required
def executive_report():

    try:

        result = (
            assessment_service
            .get_executive_summary_pdf(
                firewall_id=_firewall_param(),
                force=True
            )
        )

        summary = result["summary"]

        agent = agents_service.get_connected_agent()

        report_history_service.append_report(
            {
                "name": result["filename"].replace(".pdf", ""),
                "type": "Executive Summary",
                "generated_by": (agent or {}).get("name", "Firewall Audit Agent"),
                "firewall": _firewall_param(),
                "ts": time.time(),
                "status": "Completed",
                "size": file_size_label(result["local_file"]),
                "download_url": result["download_url"],
            },
            user_id=current_user_id(),
        )

        return render_reports(
            summary=summary,
            summary_download_url=(
                url_for("static", filename=result["download_url"])
            ),
            assessment_source=(
                summary.get("_source", "live")
            )
        )

    except Exception as e:

        return render_reports(
            summary=None,
            error=str(e)
        )

# --------------------------------------------------
# EXCEL REPORT
# --------------------------------------------------

@app.route("/generate-excel")
@login_required
def generate_excel():

    estate = (
        (request.args.get("firewall") or "").strip().lower()
        in ("all", "estate", "full", "full inventory")
    )

    try:

        if estate:

            result = (
                assessment_service
                .get_estate_excel(force=True)
            )

            # Reports centre expects a single-firewall summary shape; map the
            # cumulative estate stats onto it so the counts render correctly.
            cumulative = result.get("summary") or {}
            result["summary"] = {
                "total_controls": cumulative.get("total_controls", 0),
                "compliant": cumulative.get("total_compliant", 0),
                "non_compliant": cumulative.get("total_non_compliant", 0),
                "not_assessed": cumulative.get("total_not_assessed", 0),
            }

        else:

            result = (
                assessment_service
                .get_excel_report(
                    firewall_id=_firewall_param(),
                    force=True
                )
            )

        download_url = None

        if (
            result.get("local_file")
            and os.path.exists(
                result["local_file"]
            )
        ):

            download_url = url_for(
                "static",
                filename=result["download_url"]
            )

        agent = agents_service.get_connected_agent()

        size = file_size_label(result.get("local_file"))

        report_name = "Full Inventory Workbook" if estate else "Assessment"
        report_name = "{0}_{1}".format(
            report_name,
            timeutil.ist_now().strftime("%b_%Y"),
        )

        report_history_service.append_report(
            {
                "name": report_name,
                "type": "Workbook",
                "generated_by": (agent or {}).get("name", "Firewall Audit Agent"),
                "firewall": "estate" if estate else _firewall_param(),
                "ts": time.time(),
                "status": "Completed",
                "size": size,
                "download_url": result["download_url"],
            },
            user_id=current_user_id(),
        )

        return render_reports(
            excel_result=result,
            excel_download_url=download_url,
            assessment_source=(
                result.get("_source", "live")
            )
        )

    except Exception as e:

        return render_reports(
            excel_result=None,
            error=str(e)
        )

# --------------------------------------------------
# AGENT INSIGHTS
# --------------------------------------------------

@app.route("/insights")
@login_required
def insights():

    return render_with_css(
        "insights.html"
    )

# --------------------------------------------------
# TELEMETRY MAP
# --------------------------------------------------

@app.route("/telemetry-map")
@login_required
def telemetry_map():

    return render_with_css(
        "telemetry_map.html"
    )

# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

@app.route("/settings")
@login_required
def settings():

    # Settings is a sidebar group (Accounts / Inventory / Agents); the bare
    # path lands on the first section.
    return redirect(url_for("settings_accounts"))


@app.route("/settings/accounts")
@login_required
def settings_accounts():

    return render_with_css(
        "accounts.html",

        is_admin=_is_admin(current_user()),
    )


@app.route("/settings/inventory")
@login_required
def settings_inventory():

    return render_with_css(
        "inventory.html",

        is_admin=_is_admin(current_user()),
    )


@app.route("/settings/agents")
@login_required
def settings_agents():

    return render_with_css(
        "agents.html",

        is_admin=_is_admin(current_user()),
    )

# --------------------------------------------------
# API ROUTES
# --------------------------------------------------

@app.route("/api/compliance")
def api_compliance():

    force = (
        request.args.get(
            "refresh",
            "0"
        )
        == "1"
    )

    try:

        return jsonify(
            assessment_service
            .get_full_assessment(
                firewall_id=_firewall_param(),
                force=force
            )
        )

    except Exception as e:

        return jsonify(
            {"error": str(e)}
        ), 500


@app.route("/api/findings")
def api_findings():

    force = (
        request.args.get(
            "refresh",
            "0"
        )
        == "1"
    )

    try:

        return jsonify(
            assessment_service
            .get_posture(
                firewall_id=_firewall_param(),
                force=force
            )
        )

    except Exception as e:

        return jsonify(
            {"error": str(e)}
        ), 500


# --- Firewall Data Functions (individual connector calls) ---

@app.route("/api/firewall/inventory")
def api_firewall_inventory():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_inventory() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/health")
def api_firewall_health():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_health_status() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/ha")
def api_firewall_ha():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_ha_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/policy")
def api_firewall_policy():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_policy_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/services")
def api_firewall_services():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_security_services() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/status")
def api_firewall_status():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_full_status(), _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/routing")
def api_firewall_routing():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_routing_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/vpn")
def api_firewall_vpn():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_vpn_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/logging")
def api_firewall_logging():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_logging_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/administration")
def api_firewall_administration():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_administration_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/zone-protection")
def api_firewall_zone_protection():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_zone_protection_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/firewall/backup")
def api_firewall_backup():
    try:
        return jsonify(_relabel_firewall(firewall_data_service.get_backup_configuration() or {"error": "No data from firewall"}, _firewall_param()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/summary")
def api_summary():

    try:

        result = (
            assessment_service
            .get_executive_summary_pdf(
                firewall_id=_firewall_param(),
                force=True
            )
        )

        summary = result["summary"]

        payload = dict(summary)
        payload["download_url"] = url_for(
            "static",
            filename=result["download_url"]
        )

        agent = agents_service.get_connected_agent()
        report_history_service.append_report({
            "name": result["filename"].replace(".pdf", ""),
            "type": "Executive Summary",
            "generated_by": (agent or {}).get("name", "Firewall Audit Agent"),
            "firewall": _firewall_param(),
            "ts": time.time(),
            "status": "Completed",
            "size": file_size_label(result["local_file"]),
            "download_url": result["download_url"],
        }, user_id=current_user_id())

        return jsonify(payload)

    except Exception as e:

        return jsonify(
            {"error": str(e)}
        ), 500


@app.route("/api/excel")
def api_excel():

    try:

        result = (
            assessment_service
            .get_excel_report(
                firewall_id=_firewall_param(),
                force=True
            )
        )

        payload = dict(result)

        if result.get("local_file"):

            payload["download_url"] = url_for(
                "static",
                filename=result["download_url"]
            )

        agent = agents_service.get_connected_agent()
        report_history_service.append_report({
            "name": "Assessment_Workbook_{0}".format(timeutil.ist_now().strftime("%b_%Y")),
            "type": "Workbook",
            "generated_by": (agent or {}).get("name", "Firewall Audit Agent"),
            "firewall": _firewall_param(),
            "ts": time.time(),
            "status": "Completed",
            "size": file_size_label(result.get("local_file")),
            "download_url": result.get("download_url"),
        }, user_id=current_user_id())

        return jsonify(payload)

    except Exception as e:

        return jsonify(
            {"error": str(e)}
        ), 500


@app.route("/download-workbook")
@login_required
def download_workbook():

    try:

        result = (
            assessment_service
            .get_excel_report(
                firewall_id=_firewall_param(),
                force=True
            )
        )

        local_file = result.get("local_file")
        filename = "PaloAlto_Assessment.xlsx"

        agent = agents_service.get_connected_agent()
        report_history_service.append_report({
            "name": "Assessment_Workbook_{0}".format(timeutil.ist_now().strftime("%b_%Y")),
            "type": "Workbook",
            "generated_by": (agent or {}).get("name", "Firewall Audit Agent"),
            "firewall": _firewall_param(),
            "ts": time.time(),
            "status": "Completed",
            "size": file_size_label(local_file),
            "download_url": "reports/{0}".format(filename),
        }, user_id=current_user_id())

        return send_file(
            local_file,
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:

        return jsonify(
            {"error": str(e)}
        ), 500


@app.route("/api/agents")
def api_agents():

    return jsonify(
        {"agents": agents_service.list_agents()}
    )


@app.route("/api/agent-status")
@login_required
def api_agent_status():

    force = request.args.get("refresh", "0") == "1"
    try:
        return jsonify(
            {
                "agents": agent_status_service.get_agent_statuses(
                    force=force,
                    user_id=current_user_id(),
                )
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/agents", methods=["POST"])
@admin_required
def api_agents_add():

    payload = request.get_json(silent=True) or {}

    name = (payload.get("name") or "").strip()
    endpoint = (payload.get("endpoint") or "").strip()
    api_key = (payload.get("api_key") or "").strip()

    if not name or not endpoint or not api_key:
        return jsonify(
            {"error": "Name, endpoint, and API key are required."}
        ), 400

    agent = agents_service.add_agent(
        name=name,
        type_name=(payload.get("type") or "Custom Agent").strip(),
        endpoint=endpoint,
        api_key=api_key,
        model=(payload.get("model") or "gpt-5.1").strip(),
    )

    return jsonify({"status": "connected", "agent": agent}), 201


@app.route("/api/agents/<agent_id>", methods=["DELETE"])
@admin_required
def api_agents_remove(agent_id):

    removed = agents_service.remove_agent(agent_id)
    if not removed:
        return jsonify(
            {"error": "Agent not found."}
        ), 404

    return jsonify({"status": "removed", "agent_id": agent_id})


@app.route("/api/chat", methods=["POST"])
def api_chat():

    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip() or None
    messages = payload.get("messages")
    conversation_id = (payload.get("conversation_id") or "").strip() or None
    agent_id = (payload.get("agent_id") or "").strip() or None
    tool = payload.get("tool")

    if not message and not messages:
        return jsonify({"error": "message is required."}), 400

    try:
        result = gateway.chat(
            user_id=current_user_id(),
            message=message,
            messages=messages,
            conversation_id=conversation_id,
            agent_id=agent_id,
            tool=tool,
        )
        return jsonify(
            {
                "reply": result.get("reply"),
                "usage": result.get("usage") or {},
                "latency_ms": result.get("latency_ms"),
                "model": result.get("model"),
                "agent": result.get("agent"),
                "conversation_id": result.get("conversation_id"),
            }
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/cloudsec/action", methods=["POST"])
def api_cloudsec_action():

    payload = request.get_json(silent=True) or {}
    action = (payload.get("action") or "").strip()
    params = payload.get("params") or {}
    agent_id = (payload.get("agent_id") or "").strip() or None
    conversation_id = (payload.get("conversation_id") or "").strip() or None

    if not action:
        return jsonify({"error": "action is required."}), 400

    try:
        result = foundry_incidents.run(
            action=action,
            params=params,
            agent_id=agent_id,
            conversation_id=conversation_id,
            user_id=current_user_id(),
            record=(action != "incident_counts"),
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/netsec/info")
@login_required
def api_netsec_info():
    """Connection status + playbook catalogue for the NetSec panel."""

    from services import netsec_service

    try:
        return jsonify(netsec_service.info())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/netsec/workbook/template")
@login_required
def api_netsec_workbook_template():
    """Download the fill-in playbook template (.xlsx)."""

    from services import netsec_service

    try:
        buffer = netsec_service.build_template_bytes()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return send_file(
        buffer,
        as_attachment=True,
        download_name="netsec-playbook-template.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/api/netsec/workbook", methods=["POST"])
@login_required
def api_netsec_workbook_upload():
    """Store the uploaded workbook for the current user."""

    from services import netsec_service

    file = request.files.get("file")
    if file is None or not file.filename:
        return jsonify({"error": "A workbook file is required."}), 400
    try:
        summary = netsec_service.save_workbook(current_user_id(), file)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"uploaded": True, "summary": summary})


@app.route("/api/netsec/workbook")
@login_required
def api_netsec_workbook_get():
    """Return the summary of the user's stored workbook (if any)."""

    from services import netsec_service

    summary = netsec_service.workbook_summary(current_user_id())
    if summary is None:
        return jsonify({"summary": None}), 404
    return jsonify({"summary": summary})


@app.route("/api/netsec/playbooks/run", methods=["POST"])
@login_required
def api_netsec_playbooks_run():
    """Execute a playbook against the firewall and return per-row results."""

    from services import netsec_service

    payload = request.get_json(silent=True) or {}
    playbook_id = (payload.get("playbook_id") or "").strip()
    if not playbook_id:
        return jsonify({"error": "playbook_id is required."}), 400
    try:
        commit_flag = payload.get("commit")
        if commit_flag is not None:
            commit_flag = bool(commit_flag)
        result = netsec_service.run_playbook(
            current_user_id(), playbook_id, commit=commit_flag
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/netsec/manual", methods=["POST"])
@login_required
def api_netsec_manual():
    """Execute a single manual operation described by a chat row form."""

    from services import netsec_service

    payload = request.get_json(silent=True) or {}
    playbook_id = (payload.get("playbook_id") or "").strip()
    row = payload.get("row")
    if not playbook_id:
        return jsonify({"error": "playbook_id is required."}), 400
    try:
        commit_flag = payload.get("commit")
        if commit_flag is not None:
            commit_flag = bool(commit_flag)
        result = netsec_service.run_row(
            playbook_id, row or {}, commit=commit_flag
        )
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/tools")
def api_tools():
    return jsonify(
        {"tools": gateway.tools()}
    )


@app.route("/api/conversations")
def api_conversations():

    return jsonify(
        {"conversations": gateway.conversations(user_id=current_user_id())}
    )


@app.route("/api/conversations/<conversation_id>/messages", methods=["GET"])
def api_conversation_messages(conversation_id):

    if not session_manager.owns_conversation(conversation_id, current_user_id()):
        return jsonify({"error": "Conversation not found."}), 403

    messages = session_manager.get_messages(
        conversation_id,
        user_id=current_user_id(),
    )
    return jsonify({"messages": messages})


@app.route("/api/conversations/<conversation_id>/messages", methods=["POST"])
def api_conversation_messages_add(conversation_id):

    payload = request.get_json(silent=True) or {}
    messages = payload.get("messages") or []
    result = session_manager.add_messages(
        conversation_id,
        messages,
        user_id=current_user_id(),
    )
    if result is None:
        return jsonify({"error": "Conversation not found."}), 403
    return jsonify({"status": "ok"})


@app.route("/api/conversations/<conversation_id>/clear", methods=["POST"])
def api_conversation_clear(conversation_id):

    cleared = session_manager.clear_conversation(
        conversation_id,
        user_id=current_user_id(),
    )
    if not cleared:
        return jsonify({"error": "Conversation not found."}), 403
    return jsonify({"status": "ok"})


@app.route("/api/conversations/<conversation_id>/truncate", methods=["POST"])
def api_conversation_truncate(conversation_id):

    payload = request.get_json(silent=True) or {}
    keep = int(payload.get("keep") or 0)
    if keep < 0:
        keep = 0
    truncated = session_manager.truncate_conversation(
        conversation_id,
        keep,
        user_id=current_user_id(),
    )
    if not truncated:
        return jsonify({"error": "Conversation not found."}), 403
    return jsonify({"status": "ok"})


@app.route("/api/me")
def api_me():

    user = current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"user": user})


@app.route("/api/insights")
def api_insights():

    return jsonify(insights_service.summarize(user_id=current_user_id()))


@app.route("/api/insights/conversation/<conversation_id>")
def api_insights_conversation(conversation_id):

    summary = insights_service.summarize_conversation(
        conversation_id,
        user_id=current_user_id(),
    )
    return jsonify({"conversation": summary})


@app.route("/api/dashboard")
def api_dashboard():

    try:

        return jsonify(
            dashboard_service.get_dashboard(firewall_id=_dashboard_firewall_param())
        )

    except Exception as e:

        return jsonify(
            {"error": str(e)}
        ), 500


@app.route("/api/reports")
def api_reports():

    return jsonify(
        {"reports": report_history_service.list_reports(user_id=current_user_id())}
    )


@app.route("/api/system-status")
def api_system_status():

    return jsonify(
        system_status_service.get_system_status()
    )


@app.route("/api/telemetry-map")
def api_telemetry_map():

    agent_id = (request.args.get("agent_id") or "").strip() or None

    return jsonify(
        telemetry_map_service.build_map(agent_id=agent_id)
    )


@app.route("/api/telemetry-map/history")
def api_telemetry_map_history():

    agent_id = (request.args.get("agent_id") or "").strip() or None

    return jsonify(
        telemetry_map_service.get_history(agent_id=agent_id)
    )


# --------------------------------------------------
# ADMIN USER MANAGEMENT API
# --------------------------------------------------

@app.route("/api/admin/users")
@login_required
def api_admin_users():
    """List accounts.

    Administrators receive full account management data. Any signed-in member
    may read the roster but only sees name + role and no management fields.
    """

    if _is_admin(current_user()):
        status = (request.args.get("status") or "").strip() or None
        return jsonify({"users": users_service.list_users(status=status)})
    return jsonify({"users": users_service.list_members()})


@app.route("/api/admin/demo-requests")
@admin_required
def api_admin_demo_requests():

    return jsonify({"requests": demo_request_service.list_leads()})


@app.route("/api/admin/users/<user_id>/approve", methods=["POST"])
@admin_required
def api_admin_user_approve(user_id):

    try:
        user = users_service.set_status(user_id, "approved")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"user": user})


@app.route("/api/admin/users/<user_id>/reject", methods=["POST"])
@admin_required
def api_admin_user_reject(user_id):

    try:
        user = users_service.set_status(user_id, "rejected")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"user": user})


@app.route("/api/admin/users/<user_id>/remove", methods=["POST"])
@admin_required
def api_admin_user_remove(user_id):
    """Remove a user: sign-in is disabled but the account row is retained.

    The account is flagged ``disabled`` so ``authenticate()`` refuses any
    further sign-in. Because conversations, reports and agent insights are
    scoped per user id, the removed user's data stays in the database but is
    never listed on the workspace, reports or insights pages.
    """

    if user_id == (current_user() or {}).get("id"):
        return jsonify({"error": "You cannot remove your own account."}), 400
    try:
        user = users_service.set_status(user_id, "disabled")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"user": user})


@app.route("/api/admin/users", methods=["POST"])
@admin_required
def api_admin_users_add():

    payload = request.get_json(silent=True) or {}
    try:
        user = users_service.create_user(
            (payload.get("name") or "").strip(),
            (payload.get("email") or "").strip(),
            payload.get("password") or "",
            role=(payload.get("role") or "").strip(),
            status="approved",
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"user": user}), 201


@app.route("/api/admin/users/<user_id>/role", methods=["POST"])
@admin_required
def api_admin_user_role(user_id):

    payload = request.get_json(silent=True) or {}
    try:
        user = users_service.set_role(user_id, (payload.get("role") or "").strip())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"user": user})


# --------------------------------------------------
# FIREWALL INVENTORY API
# --------------------------------------------------

@app.route("/api/admin/firewalls")
@login_required
def api_admin_firewalls():
    """List the firewall inventory.

    Administrators see the full registry (host names, clone lineage, masked
    keys). Any signed-in member may read device name, IP and live/down status
    only - no host names, keys or clone actions.
    """

    entries = managed_firewalls_service.list_firewalls()
    if _is_admin(current_user()):
        return jsonify({"firewalls": entries})
    return jsonify(
        {
            "firewalls": [
                {
                    "id": entry["id"],
                    "device_name": entry["device_name"],
                    "host_ip": entry["host_ip"],
                    "vendor": entry.get("vendor"),
                    "port": entry.get("port"),
                    "status": entry["status"],
                }
                for entry in entries
            ]
        }
    )


@app.route("/api/admin/firewalls", methods=["POST"])
@admin_required
def api_admin_firewalls_add():

    payload = request.get_json(silent=True) or {}
    try:
        entry = managed_firewalls_service.import_firewall(
            payload.get("device_name") or "",
            payload.get("host_ip") or "",
            vendor=payload.get("vendor") or "",
            port=payload.get("port"),
            username=payload.get("username") or "",
            password=payload.get("password") or "",
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"firewall": entry}), 201


@app.route("/api/admin/firewalls/<int:firewall_id>", methods=["DELETE"])
@admin_required
def api_admin_firewalls_delete(firewall_id):

    try:
        managed_firewalls_service.remove_firewall(firewall_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"deleted": True, "id": firewall_id})


@app.route("/api/admin/firewalls/<int:firewall_id>/clone", methods=["POST"])
@admin_required
def api_admin_firewalls_clone(firewall_id):

    payload = request.get_json(silent=True) or {}
    try:
        entry = managed_firewalls_service.clone_firewall(
            firewall_id,
            (payload.get("device_name") or "").strip(),
        )
    except ValueError as exc:
        code = 404 if "not found" in str(exc) else 400
        return jsonify({"error": str(exc)}), code
    return jsonify({"firewall": entry}), 201


@app.route("/api/admin/firewalls/template")
@admin_required
def api_admin_firewalls_template():
    """Download the Firewall Inventory Excel template (Asset Inventory)."""

    buffer = firewall_bulk_service.build_template_bytes()
    return send_file(
        buffer,
        as_attachment=True,
        download_name="firewall-inventory-template.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.route("/api/admin/firewalls/bulk", methods=["POST"])
@admin_required
def api_admin_firewalls_bulk():
    """Apply a filled-in Firewall Inventory workbook (add/remove rows)."""

    file = request.files.get("file")
    try:
        summary = firewall_bulk_service.process_upload(file)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(summary)


# --------------------------------------------------
# FIREWALL INVENTORY SEARCH + FULL INVENTORY (ESTATE)
# --------------------------------------------------

@app.route("/api/firewall-inventory")
@login_required
def api_managed_firewall_inventory():
    """Return the managed firewall inventory for search pickers.

    Any signed-in user may search the inventory (AI Workspace firewall audit
    agent and the Security Operations Centre). Exposes device name, host IP,
    live/down status and clone lineage only - never host keys.
    """

    entries = managed_firewalls_service.list_firewalls()
    return jsonify({
        "firewalls": [
            {
                "id": entry["id"],
                "device_name": entry["device_name"],
                "host_name": entry.get("host_name"),
                "host_ip": entry["host_ip"],
                "status": entry["status"],
                "clone_of": entry.get("clone_of"),
                "is_clone": bool(entry.get("clone_of")),
            }
            for entry in entries
        ]
    })


@app.route("/api/estate/assessment")
@login_required
def api_estate_assessment():
    """Assess the full managed inventory and return cumulative statistics."""

    force = (
        request.args.get("refresh", "0")
        == "1"
    )
    try:
        return jsonify(
            assessment_service.get_estate_assessment(force=force)
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/estate/excel")
@login_required
def api_estate_excel():
    """Generate the aggregated full-inventory Excel workbook."""

    force = (
        request.args.get("refresh", "0")
        == "1"
    )
    try:
        result = assessment_service.get_estate_excel(force=force)

        payload = dict(result)

        if result.get("local_file"):
            payload["download_url"] = url_for(
                "static",
                filename=result["download_url"]
            )

        agent = agents_service.get_connected_agent()
        report_history_service.append_report({
            "name": result.get("filename", "").replace(".xlsx", ""),
            "type": "Workbook",
            "generated_by": (agent or {}).get("name", "Firewall Audit Agent"),
            "firewall": "estate",
            "ts": time.time(),
            "status": "Completed",
            "size": file_size_label(result.get("local_file")),
            "download_url": result.get("download_url"),
        }, user_id=current_user_id())

        return jsonify(payload)

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# --------------------------------------------------
# STARTUP VALIDATION
# --------------------------------------------------

@app.teardown_appcontext
def _teardown_session(exception):
    """Return every scoped session to the pool after the request completes."""
    try:
        from database.db import remove_session

        remove_session()
    except Exception:
        pass


def run_startup_validation():
    """Fail fast when PostgreSQL is unavailable.

    PostgreSQL is the single source of truth - there is no JSON fallback.
    The reconciliation is additive only (creates missing tables/columns/
    indexes) and never drops data.
    """
    from database.startup import validate_runtime

    try:
        report = validate_runtime()
    except Exception as exc:
        app.logger.error("%s", exc)
        raise

    app.logger.info(
        "Startup validation passed: %s | schema drift=%s | applied=%s",
        report.get("database"),
        report.get("schema_drift"),
        report.get("schema_applied"),
    )
    return report


try:
    run_startup_validation()
except Exception as exc:  # noqa: BLE001 - intentional fail-fast boot
    import sys

    app.logger.error("FATAL: %s", exc)
    sys.exit("FATAL: PostgreSQL unavailable - refusing to start without a database. {0}".format(exc))


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8003,
        debug=True
    )
