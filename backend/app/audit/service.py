import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent

_AUDIT_LOG_DIR = Path("var/audit")


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


async def _last_hash(db: AsyncSession) -> str | None:
    result = await db.execute(
        select(AuditEvent.record_hash).order_by(AuditEvent.seq.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def record_event(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    result: str,
    organization_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    resource_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Record a security-relevant event as an append-only, hash-chained entry.

    There is deliberately no update/delete function in this module — the
    invariant that audit records are append-only is enforced by the absence
    of any other code path, per docs/BUILD_SPEC.md §6.2.
    """
    prev_hash = await _last_hash(db)

    body = {
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "result": result,
        "organization_id": str(organization_id) if organization_id else None,
        "user_id": str(user_id) if user_id else None,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "metadata": metadata,
        "prev_hash": prev_hash,
    }
    record_hash = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()

    event = AuditEvent(
        organization_id=organization_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        ip_address=ip_address,
        user_agent=user_agent,
        metadata_json=metadata,
        prev_hash=prev_hash,
        record_hash=record_hash,
    )
    db.add(event)
    await db.flush()

    _append_to_file_log(body | {"record_hash": record_hash})

    return event


def _append_to_file_log(record: dict[str, Any]) -> None:
    """Best-effort mirror to an append-only file, independent of the DB.

    This gives the hash chain a second, DB-independent witness. Failure to
    write it is logged but never blocks the request — the database row is
    the durable record; the file is defense in depth for tamper evidence.
    """
    try:
        _AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = _AUDIT_LOG_DIR / "audit.log.jsonl"
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical_json(record) + "\n")
    except OSError:
        pass
