"""AP-CH/1 offline review proposal; no live integration or authority decoder."""

import time
from dataclasses import asdict, dataclass, replace

from . import publisher
from . import review_comment as comment


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Opaque evidence digest, never a model-selected URL/path to dereference."""

    kind: str
    sha256: str

    def __post_init__(self):
        comment.need(self.kind in {"analysis", "diff", "ci", "collector"})
        comment.need(publisher.hex_digest(self.sha256))


@dataclass(frozen=True, slots=True)
class Handoff:
    """Untrusted proposal. Nested envelope carries all canonical destination pins."""

    schema_version: int
    envelope: comment.Envelope
    evidence: tuple[EvidenceReference, ...]
    created_at: int
    expires_at: int

    def __post_init__(self):
        comment.need(type(self.schema_version) is int and self.schema_version == 1)
        comment.need(type(self.envelope) is comment.Envelope)
        replace(self.envelope)
        comment.need(self.envelope.policy.project is not None)
        comment.need(type(self.evidence) is tuple and 1 <= len(self.evidence) <= 8)
        for ref in self.evidence:
            comment.need(type(ref) is EvidenceReference)
            replace(ref)
        comment.need(len(set(self.evidence)) == len(self.evidence))
        comment.need(sum(ref.kind == "analysis" for ref in self.evidence) == 1)
        comment.need(type(self.created_at) is type(self.expires_at) is int)
        comment.need(0 <= self.created_at < self.expires_at <= self.created_at + 300)

    @property
    def digest(self):
        return publisher.digest(asdict(self))

    @property
    def body_sha256(self):
        return publisher.digest(self.envelope.body)


@dataclass(frozen=True, slots=True)
class OperatorApproval:
    """Trusted caller only; never parse this from model/Issue/JSON input.

    Authenticating the human and independent analysis is an external, currently
    unavailable boundary. This type supplies consistency checks, not identity.
    """

    handoff_sha256: str
    authorization: comment.ManualAuthorization

    def __post_init__(self):
        comment.need(publisher.hex_digest(self.handoff_sha256))
        comment.need(type(self.authorization) is comment.ManualAuthorization)
        replace(self.authorization)


def submit(handoff, approval=None, *, now, reader=None, writer=None, journal=None):
    """Explicit synthetic adapters only. Delegate all publication checks to #59.

    No default adapter, JSON authorization parser, CLI, network or credential
    lookup. No receipt/Ready/close action follows a synthetic COMMENT result.
    """
    started = time.monotonic()
    try:
        comment.need(type(handoff) is Handoff and type(approval) is OperatorApproval)
        replace(handoff)
        replace(approval)
        comment.need(type(now) is int)
        comment.need(handoff.created_at <= now < handoff.expires_at)
        comment.need(approval.handoff_sha256 == handoff.digest)
        grant = approval.authorization
        comment.need(grant.envelope_sha256 == handoff.envelope.digest)
        analysis = next(ref for ref in handoff.evidence if ref.kind == "analysis")
        comment.need(grant.independent_review_sha256 == analysis.sha256)
        comment.need(handoff.created_at <= grant.approved_at)
        comment.need(grant.expires_at <= handoff.expires_at)
        current = now + int(time.monotonic() - started)
        comment.need(current < handoff.expires_at)
    except Exception:
        return comment._result("BLOCKED", "handoff_blocked")
    return comment.publish(
        handoff.envelope,
        grant,
        now=current,
        reader=reader,
        writer=writer,
        journal=journal,
    )
