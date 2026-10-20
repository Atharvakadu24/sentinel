"""Registry of all 11 Sentinel SQLAlchemy ORM models.

Blueprint Section 8.1:
1. User (users)
2. UserSession (user_sessions)
3. GitHubInstallation (github_installations)
4. Project (projects)
5. Scan (scans)
6. Job (jobs)
7. Finding (findings)
8. ScanFinding (scan_findings)
9. FindingStatusHistory (finding_status_history)
10. WebhookEvent (webhook_events)
11. AIReview (ai_reviews)
"""

from app.db.models.finding import Finding, FindingStatusHistory
from app.db.models.observability import AIReview, WebhookEvent
from app.db.models.project import GitHubInstallation, Project
from app.db.models.scan import Job, Scan, ScanFinding
from app.db.models.user import User, UserSession

__all__ = [
    "AIReview",
    "Finding",
    "FindingStatusHistory",
    "GitHubInstallation",
    "Job",
    "Project",
    "Scan",
    "ScanFinding",
    "User",
    "UserSession",
    "WebhookEvent",
]
