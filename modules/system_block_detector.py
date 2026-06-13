"""
System Block Detector Module

Detects phishing attempts blocked by system-level security:
- Firewall blocks (connection refused)
- SSL/TLS certificate errors
- Connection timeouts
- DNS resolution failures
- System antivirus blocks

These are logged separately from our detector blocks to give
complete visibility into all phishing threats attempted.

Author: Research Team
Date: 2026
"""

import logging
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class SystemBlockType(Enum):
    """Types of system-level blocks"""
    FIREWALL = "firewall"
    SSL_ERROR = "ssl_error"
    CONNECTION_TIMEOUT = "connection_timeout"
    DNS_FAILURE = "dns_failure"
    ANTIVIRUS = "antivirus"
    RESET = "connection_reset"
    UNKNOWN = "unknown"


@dataclass
class SystemBlockEvent:
    """Event for system-blocked phishing attempt"""
    domain: str
    destination_ip: str
    block_type: str  # SystemBlockType value
    timestamp: float
    error_message: str
    source: str = "system_security"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON (single line for JSONL format)"""
        return json.dumps(self.to_dict())


class SystemBlockDetector:
    """Detects and logs system-blocked phishing attempts"""
    
    def __init__(self, log_dir: str = "logs"):
        """Initialize detector"""
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.events: List[SystemBlockEvent] = []
        logger.info("✓ System Block Detector initialized")
    
    def detect_and_log(
        self,
        domain: str,
        destination_ip: str,
        error_type: str,
        error_message: str,
        timestamp: Optional[float] = None
    ) -> SystemBlockEvent:
        """
        Log a system-blocked phishing attempt
        
        Args:
            domain: Domain that was blocked
            destination_ip: Destination IP that was blocked
            error_type: Type of block (firewall, ssl_error, timeout, etc.)
            error_message: Error message from system
            timestamp: Unix timestamp (defaults to now)
            
        Returns:
            SystemBlockEvent
        """
        if timestamp is None:
            timestamp = datetime.now().timestamp()
        
        # Determine block type
        block_type = self._classify_block(error_type, error_message)
        
        # Create event
        event = SystemBlockEvent(
            domain=domain,
            destination_ip=destination_ip,
            block_type=block_type.value,
            timestamp=timestamp,
            error_message=error_message
        )
        
        # Log it
        self._log_event(event)
        self.events.append(event)
        
        logger.warning(
            f"🖧 SYSTEM BLOCKED: {domain} | {block_type.value} | {error_message}"
        )
        
        return event
    
    def _classify_block(self, error_type: str, error_message: str) -> SystemBlockType:
        """Classify the type of block"""
        error_lower = (error_type + " " + error_message).lower()
        
        if "ssl" in error_lower or "certificate" in error_lower:
            return SystemBlockType.SSL_ERROR
        elif "timeout" in error_lower or "timed out" in error_lower:
            return SystemBlockType.CONNECTION_TIMEOUT
        elif "connection refused" in error_lower or "refused" in error_lower:
            return SystemBlockType.FIREWALL
        elif "dns" in error_lower or "resolve" in error_lower:
            return SystemBlockType.DNS_FAILURE
        elif "reset" in error_lower:
            return SystemBlockType.RESET
        elif "antivirus" in error_lower or "quarantine" in error_lower:
            return SystemBlockType.ANTIVIRUS
        else:
            return SystemBlockType.UNKNOWN
    
    def _log_event(self, event: SystemBlockEvent):
        """Log event to file"""
        try:
            # Create JSONL log file
            log_file = self.log_dir / f"system_blocks_{datetime.now().strftime('%Y%m%d')}.jsonl"
            with open(log_file, 'a') as f:
                f.write(event.to_json() + "\n")
            
            logger.debug(f"Logged system block to {log_file.name}")
        except Exception as e:
            logger.error(f"Error logging system block: {e}")
    
    def get_recent_blocks(self, limit: int = 20) -> List[Dict]:
        """Get recent system blocks"""
        return [e.to_dict() for e in self.events[-limit:]]
    
    def get_block_stats(self) -> Dict:
        """Get statistics about system blocks"""
        stats = {
            'total_blocks': len(self.events),
            'by_type': {},
            'recent_domains': []
        }
        
        # Count by type
        for event in self.events:
            block_type = event.block_type
            if block_type not in stats['by_type']:
                stats['by_type'][block_type] = 0
            stats['by_type'][block_type] += 1
        
        # Recent domains (last 10 unique)
        seen = set()
        for event in reversed(self.events):
            if event.domain not in seen:
                stats['recent_domains'].append({
                    'domain': event.domain,
                    'type': event.block_type,
                    'timestamp': event.timestamp
                })
                seen.add(event.domain)
                if len(stats['recent_domains']) >= 10:
                    break
        
        return stats


# Global detector instance
system_block_detector: Optional[SystemBlockDetector] = None


def get_detector() -> SystemBlockDetector:
    """Get or create global detector instance"""
    global system_block_detector
    if system_block_detector is None:
        system_block_detector = SystemBlockDetector()
    return system_block_detector
