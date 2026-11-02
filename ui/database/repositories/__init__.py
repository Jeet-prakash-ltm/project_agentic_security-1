"""Repository classes for PostgreSQL persistence.

Repositories are the only sanctioned data-access layer for services,
gateways and function apps. Each repository wraps a SQLAlchemy session.
"""

from database.repositories.agents_repository import AgentsRepository
from database.repositories.assessments_repository import AssessmentsRepository
from database.repositories.canonical_assessments_repository import (
    CanonicalAssessmentsRepository,
)
from database.repositories.canonical_zero_trust_repository import (
    CanonicalZeroTrustRepository,
)
from database.repositories.automation_jobs_repository import AutomationJobsRepository
from database.repositories.conversations_repository import ConversationsRepository
from database.repositories.demo_requests_repository import DemoRequestsRepository
from database.repositories.findings_repository import FindingsRepository
from database.repositories.firewall_jobs_repository import FirewallJobsRepository
from database.repositories.insights_repository import InsightsRepository
from database.repositories.managed_firewalls_repository import ManagedFirewallsRepository
from database.repositories.reports_repository import ReportsRepository
from database.repositories.security_jobs_repository import SecurityJobsRepository
from database.repositories.telemetry_repository import TelemetryRepository
from database.repositories.users_repository import UsersRepository
from database.repositories.zero_trust_repository import ZeroTrustRepository

__all__ = [
    "AgentsRepository",
    "AssessmentsRepository",
    "CanonicalAssessmentsRepository",
    "CanonicalZeroTrustRepository",
    "AutomationJobsRepository",
    "ConversationsRepository",
    "DemoRequestsRepository",
    "FindingsRepository",
    "FirewallJobsRepository",
    "InsightsRepository",
    "ManagedFirewallsRepository",
    "ReportsRepository",
    "SecurityJobsRepository",
    "TelemetryRepository",
    "UsersRepository",
    "ZeroTrustRepository",
]
