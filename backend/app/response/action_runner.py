import datetime
import uuid
from typing import Any
from sqlalchemy.orm import Session
from app.models.sql_models import ResponseAction, AuditLog, Notification

# Actions requiring analyst approval in strict enterprise policy
DESTRUCTIVE_ACTIONS = ["Block IP", "Revoke Session", "Block Device"]

class ControlledResponseEngine:
    def __init__(self):
        self.version = "v1.3.0-controlled-orchestration"

    def execute_action(
        self,
        db: Session,
        action_type: str,
        target: str,
        reason: str,
        evidence_summary: str,
        actor: str = "Automated Defense Policy",
        threat_id: str = None,
        incident_id: str = None,
        force_execute: bool = False
    ) -> dict[str, Any]:
        """
        Executes a controlled defensive action with audit trail and rollback configuration.
        """
        action_id = f"ACT-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        # Determine status based on destructiveness and force flag
        if action_type in DESTRUCTIVE_ACTIONS and not force_execute and actor == "Automated Defense Policy":
            status = "PENDING_APPROVAL"
            rollback_action = f"Cancel pending approval for {action_type} on {target}"
        else:
            status = "EXECUTED"
            rollback_action = self._determine_rollback(action_type, target)

        # Save to database
        db_action = ResponseAction(
            action_id=action_id,
            threat_id=threat_id,
            incident_id=incident_id,
            action_type=action_type,
            target=target,
            reason=reason,
            evidence_summary=evidence_summary,
            status=status,
            actor=actor,
            executed_at=datetime.datetime.utcnow(),
            rollback_action=rollback_action,
            rolled_back=False
        )
        db.add(db_action)

        # Create audit log
        audit = AuditLog(
            actor=actor,
            action=f"RESPONSE_ACTION_{status}: {action_type}",
            target_type="DEFENSIVE_ORCHESTRATION",
            target_id=target,
            details_json={
                "action_id": action_id,
                "reason": reason,
                "threat_id": threat_id,
                "incident_id": incident_id
            }
        )
        db.add(audit)

        # Create notification for SOC analysts
        notif = Notification(
            recipient="soc-team@enterprise.com",
            title=f"Response Executed: {action_type}",
            message=f"Action '{action_type}' applied to target '{target}'. Reason: {reason}",
            severity="CRITICAL" if "Block" in action_type else "WARNING",
            link=f"/incidents/{incident_id}" if incident_id else "/threat-detection"
        )
        db.add(notif)
        db.commit()
        db.refresh(db_action)

        return {
            "action_id": db_action.action_id,
            "action_type": db_action.action_type,
            "target": db_action.target,
            "status": db_action.status,
            "actor": db_action.actor,
            "executed_at": db_action.executed_at.isoformat(),
            "rollback_action": db_action.rollback_action,
            "reason": db_action.reason
        }

    def rollback_action(self, db: Session, action_id: str, actor: str = "Security Analyst") -> dict:
        action = db.query(ResponseAction).filter(ResponseAction.action_id == action_id).first()
        if not action:
            raise ValueError(f"Action '{action_id}' not found")
            
        if action.rolled_back:
            return {"status": "ALREADY_ROLLED_BACK", "action_id": action_id}

        action.rolled_back = True
        action.status = "ROLLED_BACK"

        # Log audit
        audit = AuditLog(
            actor=actor,
            action=f"ROLLBACK_EXECUTED: {action.action_type}",
            target_type="DEFENSIVE_ORCHESTRATION",
            target_id=action.target,
            details_json={"action_id": action_id, "rollback_rule": action.rollback_action}
        )
        db.add(audit)
        db.commit()

        return {
            "status": "ROLLED_BACK",
            "action_id": action_id,
            "message": f"Successfully reverted action '{action.action_type}' for target '{action.target}'"
        }

    def _determine_rollback(self, action_type: str, target: str) -> str:
        if action_type == "Quarantine Email":
            return f"Release email for target {target} back to user inbox"
        elif action_type == "Block URL":
            return f"Unblock URL {target} in perimeter DNS and web gateway"
        elif action_type == "Block IP":
            return f"Remove IP {target} from border firewall deny rule"
        elif action_type == "Revoke Session":
            return f"Allow new session authentication tokens for {target}"
        elif action_type == "Require MFA":
            return f"Reset step-up MFA policy for {target}"
        elif action_type == "Block Device":
            return f"Restore MDM certificate and trust status for device {target}"
        else:
            return f"Revert {action_type} on {target}"

response_engine = ControlledResponseEngine()
