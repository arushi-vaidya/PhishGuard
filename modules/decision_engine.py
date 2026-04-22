"""
Decision Engine for Phishing Detection

This module:
1. Receives predictions from inference engine
2. Makes blocking/alerting decisions based on thresholds
3. Executes preventive actions (DNS block, alert, log, etc.)
4. Maintains audit trail of all decisions
5. Integrates with system-level security controls
6. Performs REAL DNS blocking via /etc/hosts or firewall

Author: Research Team
Date: 2026
"""

import logging
from typing import Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import json
import smtplib
import numpy as np
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import DNS blocker
try:
    from dns_blocker import block_phishing_domain, unblock_phishing_domain, get_hosts_manager
    DNS_BLOCKER_AVAILABLE = True
except ImportError:
    DNS_BLOCKER_AVAILABLE = False
    block_phishing_domain = None

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionType(Enum):
    """Types of preventive actions"""
    NONE = "none"  # No action
    LOG_ONLY = "log_only"  # Log only
    ALERT = "alert"  # Generate alert
    BLOCK_DNS = "block_dns"  # Block at DNS level
    BLOCK_NETWORK = "block_network"  # Block network connection
    QUARANTINE = "quarantine"  # Quarantine/sandbox
    NOTIFY = "notify"  # Notify user/admin


@dataclass
class DetectionEvent:
    """Single phishing detection event"""
    domain: str
    destination_ip: str
    prediction: str  # "phishing" or "legitimate"
    confidence: float
    risk_level: str
    features_used: int
    timestamp: float
    alert_severity: str
    action_taken: str
    reason: str
    blocked: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        d = asdict(self)
        # Convert numpy types to native Python types
        d = {k: (float(v) if isinstance(v, (np.floating, np.integer)) else v) for k, v in d.items()}
        return d
    
    def to_json(self) -> str:
        """Convert to JSON (single line for JSONL format)"""
        return json.dumps(self.to_dict())


@dataclass
class DecisionPolicy:
    """Policy for making phishing detection decisions"""
    # Confidence thresholds
    high_confidence_threshold: float = 0.85  # Above this = high confidence
    low_confidence_threshold: float = 0.65   # Below this = low confidence
    
    # Action triggers
    block_phishing_high_confidence: bool = True
    block_phishing_medium_confidence: bool = False
    alert_phishing_any_confidence: bool = True
    alert_legitimate_low_confidence: bool = False  # Suspicious legitimate
    
    # Risk levels
    high_risk_action: ActionType = ActionType.BLOCK_DNS
    medium_risk_action: ActionType = ActionType.ALERT
    low_risk_action: ActionType = ActionType.LOG_ONLY
    
    # Notification
    send_email_alerts: bool = False
    email_recipients: List[str] = None
    
    def __post_init__(self):
        if self.email_recipients is None:
            self.email_recipients = []


class DecisionEngine:
    """Main decision engine for phishing responses"""
    
    def __init__(self, policy: Optional[DecisionPolicy] = None, log_dir: str = "logs"):
        """
        Initialize decision engine
        
        Args:
            policy: DecisionPolicy for making decisions
            log_dir: Directory for logging decisions
        """
        self.policy = policy or DecisionPolicy()
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Event history
        self.events: List[DetectionEvent] = []
        
        # Callbacks for custom actions
        self.action_handlers: Dict[ActionType, Callable] = {
            ActionType.LOG_ONLY: self._handle_log_only,
            ActionType.ALERT: self._handle_alert,
            ActionType.BLOCK_DNS: self._handle_block_dns,
            ActionType.BLOCK_NETWORK: self._handle_block_network,
            ActionType.NOTIFY: self._handle_notify,
        }
        
        # Statistics
        self.stats = {
            'total_decisions': 0,
            'phishing_blocked': 0,
            'phishing_alerted': 0,
            'false_positives': 0,
            'events_logged': 0,
        }
        
        logger.info("✓ Decision Engine initialized")
    
    def decide(
        self,
        domain: str,
        destination_ip: str,
        prediction: str,
        confidence: float,
        risk_level: str,
        features_used: int,
        timestamp: float
    ) -> DetectionEvent:
        """
        Make decision based on prediction and policy
        
        Args:
            domain: Domain being connected to
            destination_ip: Destination IP
            prediction: "phishing" or "legitimate"
            confidence: Confidence score (0.0-1.0)
            risk_level: "low", "medium", "high"
            features_used: Number of features used
            timestamp: Unix timestamp
            
        Returns:
            DetectionEvent with decision and action
        """
        
        # Determine alert severity
        alert_severity = self._get_alert_severity(prediction, confidence, risk_level)
        
        # Determine action
        action, reason = self._get_action(prediction, confidence, risk_level)
        
        # Create event
        event = DetectionEvent(
            domain=domain,
            destination_ip=destination_ip,
            prediction=prediction,
            confidence=confidence,
            risk_level=risk_level,
            features_used=features_used,
            timestamp=timestamp,
            alert_severity=alert_severity.value,
            action_taken=action.value,
            reason=reason,
            blocked=(action in [ActionType.BLOCK_DNS, ActionType.BLOCK_NETWORK])
        )
        
        # Execute action
        self._execute_action(event, action)
        
        # Log event
        self._log_event(event)
        self.events.append(event)
        
        # Update statistics
        self.stats['total_decisions'] += 1
        if event.blocked:
            self.stats['phishing_blocked'] += 1
        if action == ActionType.ALERT:
            self.stats['phishing_alerted'] += 1
        
        return event
    
    def _get_alert_severity(self, prediction: str, confidence: float, risk_level: str) -> AlertSeverity:
        """Determine alert severity level"""
        if prediction == "phishing":
            if confidence >= self.policy.high_confidence_threshold:
                return AlertSeverity.CRITICAL
            elif confidence >= self.policy.low_confidence_threshold:
                return AlertSeverity.HIGH
            else:
                return AlertSeverity.MEDIUM
        else:  # legitimate
            if confidence < self.policy.low_confidence_threshold:
                return AlertSeverity.MEDIUM  # Suspicious legitimate
            else:
                return AlertSeverity.LOW
    
    def _get_action(self, prediction: str, confidence: float, risk_level: str) -> tuple:
        """Determine what action to take"""
        
        if prediction == "phishing":
            if confidence >= self.policy.high_confidence_threshold and self.policy.block_phishing_high_confidence:
                return ActionType.BLOCK_DNS, f"High confidence phishing ({confidence:.2%})"
            elif confidence >= self.policy.low_confidence_threshold and self.policy.alert_phishing_any_confidence:
                return ActionType.ALERT, f"Phishing detected ({confidence:.2%})"
            elif self.policy.alert_phishing_any_confidence:
                return ActionType.ALERT, f"Possible phishing ({confidence:.2%})"
            else:
                return ActionType.LOG_ONLY, f"Phishing detected but no action configured"
        else:
            # Legitimate but low confidence
            if confidence < self.policy.low_confidence_threshold and self.policy.alert_legitimate_low_confidence:
                return ActionType.ALERT, f"Legitimate but suspicious ({confidence:.2%})"
            else:
                return ActionType.LOG_ONLY, "Legitimate domain"
        
        return ActionType.NONE, "No action"
    
    def _execute_action(self, event: DetectionEvent, action: ActionType):
        """Execute the decided action"""
        if action in self.action_handlers:
            handler = self.action_handlers[action]
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Error executing action {action.value}: {e}")
    
    def _handle_log_only(self, event: DetectionEvent):
        """Log-only action"""
        logger.info(f"[LOG] {event.domain} - {event.prediction} ({event.confidence:.2%})")
    
    def _handle_alert(self, event: DetectionEvent):
        """Generate alert"""
        logger.warning(
            f"🚨 ALERT: {event.domain} | "
            f"Prediction: {event.prediction.upper()} | "
            f"Confidence: {event.confidence:.2%} | "
            f"IP: {event.destination_ip}"
        )
        
        # Notify user
        self._handle_notify(event)
        
        # Send email if configured
        if self.policy.send_email_alerts and self.policy.email_recipients:
            self._send_email_alert(event)
    
    def _handle_block_dns(self, event: DetectionEvent):
        """Block at DNS level using /etc/hosts modification"""
        logger.critical(
            f"🛑 BLOCKING (DNS): {event.domain} | "
            f"Confidence: {event.confidence:.2%} | "
            f"IP: {event.destination_ip}"
        )
        
        # Notify user of block
        self._handle_notify(event)
        
        # Use real DNS blocking
        if DNS_BLOCKER_AVAILABLE and block_phishing_domain:
            try:
                result = block_phishing_domain(
                    domain=event.domain,
                    ip_address=event.destination_ip,
                    use_hosts=True,
                    use_firewall=False
                )
                
                if result.get('hosts'):
                    logger.info(f"  ✓ REAL DNS BLOCK APPLIED: {event.domain} redirected to 127.0.0.1")
                    logger.info(f"  → All connections to {event.domain} will now resolve to localhost")
                else:
                    logger.warning(f"  ⚠ DNS block failed (likely permission issue)")
                    logger.info(f"  → Run with 'sudo' to enable real DNS blocking")
                    self._simulate_dns_block(event)
            except Exception as e:
                logger.error(f"  ✗ Error in DNS blocking: {e}")
                self._simulate_dns_block(event)
        else:
            logger.warning(f"  ⚠ DNS blocker not available, using simulation")
            self._simulate_dns_block(event)
    
    
    def _handle_block_network(self, event: DetectionEvent):
        """Block at network level"""
        logger.critical(
            f"🛑 BLOCKING (NETWORK): {event.domain} | "
            f"IP: {event.destination_ip} | "
            f"Confidence: {event.confidence:.2%}"
        )
        
        # Notify user of block
        self._handle_notify(event)
        
        # In production: Call firewall/IDS to block
        self._simulate_network_block(event)
    
    def _handle_notify(self, event: DetectionEvent):
        """Notify user/admin"""
        logger.warning(f"📢 NOTIFY USER: {event.domain} ({event.prediction})")
        
        # Create user-facing message
        if event.blocked:
            # Blocked - show warning
            notification = (
                f"\n{'='*70}\n"
                f"🛑 SECURITY ALERT - BLOCKED\n"
                f"{'='*70}\n"
                f"Domain: {event.domain}\n"
                f"Status: DANGEROUS - This site has been blocked\n"
                f"Reason: {event.reason}\n"
                f"Confidence: {event.confidence:.2%}\n"
                f"Time: {datetime.fromtimestamp(event.timestamp)}\n"
                f"\n⚠️  This domain was flagged as phishing/malicious\n"
                f"   and has been blocked for your protection.\n"
                f"{'='*70}\n"
            )
        else:
            # Alert - show warning
            notification = (
                f"\n{'='*70}\n"
                f"⚠️  SECURITY WARNING\n"
                f"{'='*70}\n"
                f"Domain: {event.domain}\n"
                f"Status: SUSPICIOUS - Possible phishing attempt\n"
                f"Reason: {event.reason}\n"
                f"Confidence: {event.confidence:.2%}\n"
                f"Time: {datetime.fromtimestamp(event.timestamp)}\n"
                f"\n📌 Be cautious with this domain.\n"
                f"{'='*70}\n"
            )
        
        logger.info(f"[USER NOTIFICATION]{notification}")
        
        # In production: Show OS notification popup, browser extension alert, etc.
        # Example: call osascript on macOS, notify-send on Linux, Windows Toast Notification
        self._show_system_notification(event)
        
        # Send email if configured
        if self.policy.send_email_alerts and self.policy.email_recipients:
            self._send_email_alert(event)
    
    def _show_system_notification(self, event: DetectionEvent):
        """Show system notification (simulated)"""
        if event.blocked:
            msg = f"🛑 BLOCKED: {event.domain} (Phishing detected - {event.confidence:.0%} confidence)"
        else:
            msg = f"⚠️ WARNING: {event.domain} (Suspicious - {event.confidence:.0%} confidence)"
        
        logger.info(f"[SYSTEM NOTIFICATION] {msg}")
    
    def _log_event(self, event: DetectionEvent):
        """Log event to file"""
        # Save to JSON log
        log_file = self.log_dir / f"detections_{datetime.now().strftime('%Y%m%d')}.jsonl"
        
        with open(log_file, 'a') as f:
            f.write(event.to_json() + "\n")
        
        self.stats['events_logged'] += 1
    
    def _simulate_dns_block(self, event: DetectionEvent):
        """Simulate DNS block (for testing or when real blocking fails)"""
        block_file = self.log_dir / "blocked_domains.txt"
        with open(block_file, 'a') as f:
            f.write(f"{event.destination_ip} {event.domain} # {datetime.now()}\n")
        logger.info(f"  → Simulated DNS block: {event.domain} ({event.destination_ip})")
    
    
    def _simulate_network_block(self, event: DetectionEvent):
        """Simulate network block (for testing)"""
        block_file = self.log_dir / "blocked_ips.txt"
        with open(block_file, 'a') as f:
            f.write(f"{event.destination_ip} # {event.domain} {datetime.now()}\n")
        logger.info(f"  → Simulated network block: {event.destination_ip}")
    
    def _send_email_alert(self, event: DetectionEvent):
        """Send email alert (requires SMTP configuration)"""
        try:
            subject = f"🚨 Phishing Alert: {event.domain}"
            body = f"""
Phishing Detection Alert

Domain: {event.domain}
IP Address: {event.destination_ip}
Prediction: {event.prediction.upper()}
Confidence: {event.confidence:.2%}
Risk Level: {event.risk_level.upper()}
Timestamp: {datetime.fromtimestamp(event.timestamp)}

Action Taken: {event.action_taken}
Reason: {event.reason}

Please review this detection and take appropriate action.
            """
            
            logger.info(f"[EMAIL ALERT] Would send to {self.policy.email_recipients}")
            # In production: actually send via SMTP
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def get_statistics(self) -> Dict:
        """Get decision statistics"""
        return {
            **self.stats,
            'blocking_rate': self.stats['phishing_blocked'] / max(self.stats['total_decisions'], 1),
        }
    
    def get_recent_events(self, count: int = 10) -> List[DetectionEvent]:
        """Get recent detection events"""
        return self.events[-count:]
    
    def get_blocked_domains(self) -> List[str]:
        """Get list of blocked domains"""
        return [e.domain for e in self.events if e.blocked]
    
    def set_action_handler(self, action_type: ActionType, handler: Callable):
        """Register custom action handler"""
        self.action_handlers[action_type] = handler
        logger.info(f"Registered custom handler for {action_type.value}")
    
    def print_summary(self):
        """Print decision summary"""
        stats = self.get_statistics()
        
        print("\n" + "="*80)
        print("DECISION ENGINE SUMMARY")
        print("="*80)
        print(f"Total Decisions: {stats['total_decisions']}")
        print(f"Phishing Blocked: {stats['phishing_blocked']}")
        print(f"Phishing Alerted: {stats['phishing_alerted']}")
        print(f"Blocking Rate: {stats['blocking_rate']:.2%}")
        print(f"Events Logged: {stats['events_logged']}")
        
        if self.get_blocked_domains():
            print(f"\nBlocked Domains: {len(self.get_blocked_domains())}")
            for domain in self.get_blocked_domains()[:5]:
                print(f"  • {domain}")
            if len(self.get_blocked_domains()) > 5:
                print(f"  ... and {len(self.get_blocked_domains()) - 5} more")
        
        print("="*80 + "\n")


class AdaptiveDecisionEngine(DecisionEngine):
    """Decision engine that adapts based on outcomes"""
    
    def __init__(self, policy: Optional[DecisionPolicy] = None, log_dir: str = "logs"):
        super().__init__(policy, log_dir)
        self.feedback_history = []
    
    def provide_feedback(self, event_index: int, was_correct: bool, feedback: str = ""):
        """
        Provide feedback on a decision
        
        Args:
            event_index: Index of event in history
            was_correct: Whether the decision was correct
            feedback: User feedback
        """
        if 0 <= event_index < len(self.events):
            event = self.events[event_index]
            self.feedback_history.append({
                'event': event.to_dict(),
                'was_correct': was_correct,
                'feedback': feedback,
                'timestamp': datetime.now().isoformat()
            })
            
            # Could adjust policy based on feedback
            if not was_correct:
                logger.warning(f"Decision corrected for {event.domain}: {feedback}")
    
    def get_accuracy(self) -> float:
        """Calculate accuracy based on feedback"""
        if not self.feedback_history:
            return 0.0
        
        correct = sum(1 for f in self.feedback_history if f['was_correct'])
        return correct / len(self.feedback_history)


if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create policy
    policy = DecisionPolicy(
        block_phishing_high_confidence=True,
        alert_phishing_any_confidence=True,
    )
    
    # Create engine
    engine = DecisionEngine(policy)
    
    # Test decisions
    test_cases = [
        ("google.com", "142.250.185.46", "legitimate", 0.95, "low"),
        ("paypal-verify.com", "185.25.51.205", "phishing", 0.99, "high"),
        ("suspicious-site.net", "185.225.69.24", "phishing", 0.72, "medium"),
    ]
    
    print("\n" + "="*80)
    print("TESTING DECISION ENGINE")
    print("="*80 + "\n")
    
    for domain, ip, pred, conf, risk in test_cases:
        event = engine.decide(domain, ip, pred, conf, risk, 41, datetime.now().timestamp())
        print(f"\n{event.domain}: {event.action_taken} ({event.reason})")
    
    engine.print_summary()
