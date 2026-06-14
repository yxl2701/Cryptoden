"""Permission confirmation request objects for agent tool calls."""

from dataclasses import dataclass
from uuid import uuid4

from .policy import PermissionDecision


@dataclass
class PermissionRequest:
    request_id: str
    action: str
    target: str
    reason: str
    risk_level: str
    decision: str = "pending"

    @classmethod
    def from_decision(cls, action: str, target: str, decision: PermissionDecision):
        return cls(
            request_id=str(uuid4()),
            action=action,
            target=target,
            reason=decision.reason,
            risk_level="high",
        )

    def allow_once(self):
        self.decision = "allow_once"
        return self

    def deny(self):
        self.decision = "deny"
        return self

    def stop(self):
        self.decision = "stop"
        return self
