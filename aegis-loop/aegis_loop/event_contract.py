from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

EventActor = Literal[
    "victim",
    "guard",
    "red",
    "blue",
    "incident",
    "scope",
    "editor",
    "system",
]
EventType = Literal[
    "run_started",
    "run_finished",
    "session_started",
    "context_item_added",
    "tool_call",
    "decision",
    "approval_requested",
    "approval_resolved",
    "attack_attempt",
    "attack_result",
    "policy_proposed",
    "policy_validated",
    "policy_applied",
    "policy_generalized",
    "patch_rejected",
    "path_hardened",
    "path_needs_human",
    "incident_detected",
    "session_quarantined",
    "session_released",
    "incident_resolved",
    "code_change_detected",
    "paths_scoped",
    "score_updated",
    "workspace_created",
    "file_saved",
    "fix_proposed",
    "fix_gate",
    "fix_approved",
    "fix_merged",
    "policy_retired",
    "fix_reverted",
    "policy_restored",
]

REQUIRED_DATA_FIELDS: dict[str, set[str]] = {
    "run_started": {"kind", "params"},
    "run_finished": {"kind", "status", "summary"},
    "session_started": {"role", "task", "origin"},
    "context_item_added": {
        "source",
        "trust",
        "sensitivity",
        "excerpt",
        "digest",
    },
    "tool_call": {"tool", "args", "kind", "channel"},
    "decision": {"tool", "verdict", "rule_id", "explain"},
    "approval_requested": {"approval_id", "tool", "args", "rule_id"},
    "approval_resolved": {"approval_id", "resolution", "by"},
    "attack_attempt": {"attack_id", "strategy", "goal", "class", "run_index"},
    "attack_result": {
        "attack_id",
        "strategy",
        "goal",
        "result",
        "successes",
        "runs",
        "evidence",
        "session_ids",
    },
    "policy_proposed": {"policy_id", "rules", "origin_attack_id", "template"},
    "policy_validated": {"policy_id", "gates"},
    "policy_applied": {"policy_id", "rule_ids", "version"},
    "policy_generalized": {"policy_id", "from_rule", "to_rule", "reason"},
    "patch_rejected": {"policy_id", "gate", "reason"},
    "path_hardened": {"rounds", "attempts", "strategies_tried"},
    "path_needs_human": {"reason"},
    "incident_detected": {"incident_id", "detector", "severity", "entry_hint"},
    "session_quarantined": {"incident_id", "ttl_s"},
    "session_released": {"incident_id", "by"},
    "incident_resolved": {
        "incident_id",
        "policy_id",
        "report_path",
        "t_detect_ms",
        "t_contain_ms",
        "t_patch_ms",
    },
    "code_change_detected": {"base", "head", "files"},
    "paths_scoped": {"affected", "skipped"},
    "score_updated": {
        "attack_success_before",
        "attack_success_after",
        "benign_passed",
        "benign_total",
        "holdout_before",
        "holdout_after",
    },
    "workspace_created": {"workspace_id", "path"},
    "file_saved": {"workspace_id", "path", "diff"},
    "fix_proposed": {"fix_id", "diff"},
    "fix_gate": {"fix_id", "gate", "ok", "reason"},
    "fix_approved": {"fix_id", "by"},
    "fix_merged": {"fix_id", "commit"},
    "policy_retired": {"policy_id", "reason"},
    "fix_reverted": {"fix_id", "reason"},
    "policy_restored": {"policy_id", "version"},
}


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    v: Literal[1] = 1
    seq: int = Field(ge=1)
    ts: str
    actor: EventActor
    type: EventType
    run_id: str
    session_id: str | None = None
    path: str | None = None
    data: dict[str, Any]

    @model_validator(mode="after")
    def validate_event_data(self) -> "EventEnvelope":
        missing = REQUIRED_DATA_FIELDS[self.type] - self.data.keys()
        if missing:
            missing_fields = ", ".join(sorted(missing))
            raise ValueError(
                f"event {self.type} is missing required data fields: {missing_fields}"
            )
        if self.type == "policy_proposed" and not isinstance(self.data["rules"], list):
            raise ValueError("policy_proposed.rules must be a list")
        return self
