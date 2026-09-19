"""The AppSec engine set (docs/BUILD_SPEC.md §26 Phase 14).

Explicit registration, same as the API and AI registries: an engine that is
not deliberately listed here does not run.
"""

from app.core.appsec.contract import AppSecEngine
from app.core.appsec.iac.checkov_engine import CheckovEngine
from app.core.appsec.sast.bandit_engine import BanditEngine
from app.core.appsec.sast.semgrep_engine import SemgrepEngine
from app.core.appsec.sca.pip_audit_engine import PipAuditEngine
from app.core.appsec.secrets.engine import SecretScanEngine
from app.core.appsec.secrets.gitleaks_engine import GitleaksEngine


def appsec_engines(*, allow_advisory_lookup: bool = False) -> list[AppSecEngine]:
    return [
        SemgrepEngine(),
        BanditEngine(),
        PipAuditEngine(allow_advisory_lookup=allow_advisory_lookup),
        SecretScanEngine(),
        # Two secrets engines on purpose: the one above reads the working tree,
        # this one reads the git history. A credential removed in a later commit
        # is still in the history, and one that was ever pushed is compromised.
        GitleaksEngine(),
        CheckovEngine(),
    ]
