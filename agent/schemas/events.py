# agent/schemas/events.py - FIXED Linux Event Schemas
"""
Linux Event Data Schemas - FIXED VERSION WITH EventSeverity (NO REGISTRY)
Compatible with EDR_System database structure and Linux systems
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import logging

# Define EventType enum - Linux specific (NO REGISTRY)
class EventType(Enum):
    """Event types for Linux systems (no Registry)"""
    PROCESS = "Process"
    FILE = "File" 
    NETWORK = "Network"
    AUTHENTICATION = "Authentication"
    SYSTEM = "System"
    CONTAINER_SECURITY = "Container_Security"
    SERVICE_STARTED = "Service_Started"
    SERVICE_STOPPED = "Service_Stopped"
    SERVICE_REMOVED = "Service_Removed"
    SYSTEM_EVENT = "System_Event"
    SYSTEM_PERFORMANCE = "System_Performance"
    SYSTEM_SECURITY = "System_Security"
    # Linux specific events
    KERNEL = "Kernel"
    SYSCTL = "Sysctl"  # /proc/sys monitoring
    PROCFS = "Procfs"  # /proc filesystem monitoring
    SYSFS = "Sysfs"    # /sys filesystem monitoring

class EventAction(Enum):
    """Event actions for Linux systems"""
    # Process actions
    START = "Start"
    STOP = "Stop" 
    CREATE = "Create"
    TERMINATE = "Terminate"
    
    # File actions  
    READ = "Read"
    WRITE = "Write"
    DELETE = "Delete"
    MODIFY = "Modify"
    RENAME = "Rename"
    COPY = "Copy"
    MOVE = "Move"
    ACCESS = "Access"
    
    # Network actions
    CONNECT = "Connect"
    DISCONNECT = "Disconnect"
    LISTEN = "Listen"
    SEND = "Send"
    RECEIVE = "Receive"
    
    # Authentication actions
    LOGIN = "Login"
    LOGOUT = "Logout"
    LOGIN_FAILED = "Login_Failed"
    SUDO = "Sudo"
    SU = "Su"
    
    # System actions
    SERVICE_START = "Service_Start"
    SERVICE_STOP = "Service_Stop"
    MOUNT = "Mount"
    UNMOUNT = "Unmount"
    
    # Security actions
    SUSPICIOUS_ACTIVITY = "Suspicious"
    THREAT_DETECTED = "Threat"
    MALWARE_DETECTED = "Malware"
    
    # General actions
    EXECUTE = "Execute"
    LOAD = "Load"
    UNLOAD = "Unload"
    RESOURCE_USAGE = "Resource_Usage"

# FIXED: Add missing EventSeverity enum
class EventSeverity(Enum):
    """Event severity levels"""
    CRITICAL = "Critical"
    HIGH = "High" 
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    
    # Additional severity levels for compatibility
    INFORMATION = "Info"
    WARNING = "Medium"
    ERROR = "High"
    FATAL = "Critical"

@dataclass
class EventData:
    """✅ FIXED: Event Data with proper agent_id validation"""
    
    # ✅ FIXED: Core event information
    event_type: str
    event_action: str
    event_timestamp: datetime = field(default_factory=datetime.now)
    severity: str = "Info"
    
    # ✅ FIXED: Agent information - REQUIRED
    agent_id: Optional[str] = None
    
    # Process information
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    process_user: Optional[str] = None
    
    # File information
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_extension: Optional[str] = None
    
    # Network information
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    
    # Authentication information
    login_user: Optional[str] = None
    login_type: Optional[str] = None
    login_result: Optional[str] = None
    
    # Detection information
    threat_level: str = "None"
    risk_score: int = 0
    analyzed: bool = False
    
    # Additional information
    description: Optional[str] = None
    raw_event_data: Optional[dict] = None
    
    def __post_init__(self):
        """✅ FIXED: Post-initialization with agent_id validation"""
        # ✅ FIXED: Critical agent_id validation
        if not self.agent_id:
            logger = logging.getLogger(__name__)
            logger.error(f"❌ CRITICAL: EventData created without agent_id - Type: {self.event_type}")
        
        # ✅ FIXED: Normalize severity
        severity_map = {
            'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium',
            'LOW': 'Low', 'INFO': 'Info', 'INFORMATION': 'Info'
        }
        self.severity = severity_map.get(self.severity.upper(), self.severity)
        
        # ✅ FIXED: Generate description if missing
        if not self.description:
            self.description = self._generate_description()
        
        # ✅ FIXED: Prepare raw_event_data as dict
        if self.raw_event_data is None:
            self.raw_event_data = {}
        
        self.raw_event_data.update({
            'platform': 'linux',
            'event_timestamp': self.event_timestamp.isoformat(),
            'agent_id_validated': bool(self.agent_id),
            'database_compatible': True
        })
    
    def _generate_description(self) -> str:
        """✅ FIXED: Generate event description"""
        try:
            if self.event_type == "Process":
                return f"Linux Process {self.event_action}: {self.process_name or 'Unknown'}"
            elif self.event_type == "File":
                return f"Linux File {self.event_action}: {self.file_name or 'Unknown'}"
            elif self.event_type == "Network":
                return f"Linux Network {self.event_action}: {self.destination_ip or 'Unknown'}"
            elif self.event_type == "Authentication":
                return f"Linux Auth {self.event_action}: {self.login_user or 'Unknown'}"
            else:
                return f"Linux {self.event_type} Event: {self.event_action}"
        except:
            return f"Linux Event: {self.event_type} - {self.event_action}"
    
    def to_dict(self) -> Dict[str, Any]:
        """✅ FIXED: Convert to dictionary with agent_id validation"""
        # ✅ FIXED: Critical validation
        if not self.agent_id:
            return {'error': 'Event missing required agent_id field'}
        
        data = {
            'agent_id': self.agent_id,
            'event_type': self.event_type,
            'event_action': self.event_action,
            'event_timestamp': self.event_timestamp.isoformat(),
            'severity': self.severity,
            'process_id': self.process_id,
            'process_name': self.process_name,
            'process_path': self.process_path,
            'command_line': self.command_line,
            'parent_pid': self.parent_pid,
            'process_user': self.process_user,
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_extension': self.file_extension,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'direction': self.direction,
            'login_user': self.login_user,
            'login_type': self.login_type,
            'login_result': self.login_result,
            'threat_level': self.threat_level,
            'risk_score': self.risk_score,
            'analyzed': self.analyzed,
            'description': self.description,
            'raw_event_data': self.raw_event_data
        }
        
        # ✅ FIXED: Remove None values
        return {k: v for k, v in data.items() if v is not None}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventData':
        """Create EventData from dictionary (for server responses)"""
        try:
            # Handle datetime conversion
            if 'event_timestamp' in data and isinstance(data['event_timestamp'], str):
                data['event_timestamp'] = datetime.fromisoformat(data['event_timestamp'].replace('Z', '+00:00'))
            
            return cls(**data)
            
        except Exception as e:
            # Return minimal event on error
            return cls(
                event_type="System",
                event_action="Access",
                description=f"Error creating event from dict: {e}",
                raw_event_data={'platform': 'linux', 'error': str(e), 'no_registry': True}
            )
    
    def set_threat_indicators(self, threat_score: int, threat_description: str = None):
        """Set threat indicators for the event"""
        try:
            self.risk_score = min(max(threat_score, 0), 100)
            
            # Set threat level based on score
            if threat_score >= 70:
                self.threat_level = "Malicious"
            elif threat_score >= 30:
                self.threat_level = "Suspicious"
            else:
                self.threat_level = "None"
            
            # Adjust severity based on threat score
            if threat_score >= 90:
                self.severity = "Critical"
            elif threat_score >= 70:
                self.severity = "High"
            elif threat_score >= 50:
                self.severity = "Medium"
            elif threat_score >= 30:
                self.severity = "Low"
            
            # Update description
            if threat_description:
                self.description = f"{self.description} - {threat_description}"
            
            # Mark as analyzed
            self.analyzed = True
            self.analyzed_at = datetime.now()
            
            # Update raw event data
            self._prepare_raw_event_data()
            
        except Exception:
            pass
    
    def is_suspicious(self) -> bool:
        """Check if event has suspicious indicators"""
        return self.threat_level in ['Suspicious', 'Malicious'] or self.risk_score >= 30

# Factory functions for creating database-compatible events
def create_process_event(pid: int, name: str, action: str = "Start", **kwargs) -> EventData:
    """Create process event compatible with database"""
    return EventData(
        event_type="Process",
        event_action=action,
        process_id=pid,
        process_name=name,
        **kwargs
    )

def create_file_event(file_path: str, operation: str, **kwargs) -> EventData:
    """Create file event compatible with database"""
    file_name = file_path.split('/')[-1] if '/' in file_path else file_path
    return EventData(
        event_type="File",
        event_action=operation,
        file_path=file_path,
        file_name=file_name,
        file_operation=operation,
        **kwargs
    )

def create_network_event(source_ip: str, dest_ip: str, action: str = "Connect", **kwargs) -> EventData:
    """Create network event compatible with database"""
    return EventData(
        event_type="Network",
        event_action=action,
        source_ip=source_ip,
        destination_ip=dest_ip,
        **kwargs
    )

def create_auth_event(user: str, login_type: str, result: str, **kwargs) -> EventData:
    """Create authentication event compatible with database"""
    action = "Login" if result.lower() == "success" else "Login_Failed"
    severity = "Info" if result.lower() == "success" else "Medium"
    
    return EventData(
        event_type="Authentication",
        event_action=action,
        login_user=user,
        login_type=login_type,
        login_result=result,
        severity=severity,
        **kwargs
    )

def create_system_event(action: str, **kwargs) -> EventData:
    """Create system event compatible with database"""
    return EventData(
        event_type="System",
        event_action=action,
        **kwargs
    )

# Linux specific factory functions
def create_procfs_event(proc_path: str, action: str = "Access", **kwargs) -> EventData:
    """Create /proc filesystem event"""
    return EventData(
        event_type="Procfs",
        event_action=action,
        file_path=proc_path,
        description=f"Linux /proc access: {proc_path}",
        **kwargs
    )

def create_sysfs_event(sys_path: str, action: str = "Access", **kwargs) -> EventData:
    """Create /sys filesystem event"""
    return EventData(
        event_type="Sysfs", 
        event_action=action,
        file_path=sys_path,
        description=f"Linux /sys access: {sys_path}",
        **kwargs
    )

def create_sysctl_event(sysctl_key: str, action: str = "Modify", **kwargs) -> EventData:
    """Create sysctl (kernel parameter) event"""
    return EventData(
        event_type="Sysctl",
        event_action=action,
        description=f"Linux sysctl change: {sysctl_key}",
        raw_event_data={'sysctl_key': sysctl_key, 'platform': 'linux'},
        **kwargs
    )

def validate_event_for_database(event: EventData) -> tuple[bool, str]:
    """Validate event data for database insertion"""
    try:
        # Check required fields
        if not event.agent_id:
            return False, "Missing required field: agent_id"
        
        if not event.event_type:
            return False, "Missing required field: event_type"
        
        if not event.event_action:
            return False, "Missing required field: event_action"
        
        # Validate event_type (Linux - no Registry)
        valid_event_types = ["Process", "File", "Network", "Authentication", "System", "Procfs", "Sysfs", "Sysctl", "Kernel"]
        if event.event_type not in valid_event_types:
            return False, f"Invalid event_type: {event.event_type}. Must be one of {valid_event_types}"
        
        # Validate severity
        valid_severities = ["Critical", "High", "Medium", "Low", "Info"]
        if event.severity not in valid_severities:
            return False, f"Invalid severity: {event.severity}. Must be one of {valid_severities}"
        
        # Validate threat_level
        valid_threat_levels = ["None", "Suspicious", "Malicious"]
        if event.threat_level not in valid_threat_levels:
            return False, f"Invalid threat_level: {event.threat_level}. Must be one of {valid_threat_levels}"
        
        # Validate risk_score
        if not (0 <= event.risk_score <= 100):
            return False, f"Invalid risk_score: {event.risk_score}. Must be between 0 and 100"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Validation error: {e}"