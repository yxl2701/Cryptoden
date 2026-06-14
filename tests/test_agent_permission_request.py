import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.permission_request import PermissionRequest
from agent.policy import PermissionDecision


def test_permission_request_from_command_decision():
    request = PermissionRequest.from_decision(
        "run_command",
        "pytest",
        PermissionDecision("ask", "command_requires_confirmation"),
    )

    assert request.request_id
    assert request.action == "run_command"
    assert request.target == "pytest"
    assert request.reason == "command_requires_confirmation"
    assert request.risk_level == "high"
    assert request.decision == "pending"


def test_permission_request_decisions():
    request = PermissionRequest.from_decision("run_command", "pytest", PermissionDecision("ask"))

    assert request.allow_once().decision == "allow_once"
    assert request.deny().decision == "deny"
    assert request.stop().decision == "stop"
