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
    """✅ FIXED: Event Data with proper agent_id validation and server schema compatibility"""
    
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
    parent_process_name: Optional[str] = None  # Added for server compatibility
    process_user: Optional[str] = None
    process_hash: Optional[str] = None  # Added for server compatibility
    
    # File information
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None  # Added for server compatibility
    file_extension: Optional[str] = None
    file_operation: Optional[str] = None  # Added for server compatibility
    
    # Network information
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    
    # Registry information (not used in Linux but required by server schema)
    registry_key: Optional[str] = None
    registry_value_name: Optional[str] = None
    registry_value_data: Optional[str] = None
    registry_operation: Optional[str] = None
    
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
        """✅ FIXED: Convert to dictionary matching server EventSubmissionRequest schema exactly"""
        # ✅ FIXED: Critical validation
        if not self.agent_id:
            return {'error': 'Event missing required agent_id field'}
        
        # ✅ FIXED: Handle event_type properly
        event_type_value = self.event_type
        if hasattr(self.event_type, 'value'):
            event_type_value = self.event_type.value
        elif isinstance(self.event_type, str):
            event_type_value = self.event_type
        
        # ✅ FIXED: Handle event_action properly
        event_action_value = self.event_action
        if hasattr(self.event_action, 'value'):
            event_action_value = self.event_action.value
        elif isinstance(self.event_action, str):
            event_action_value = self.event_action
        
        # ✅ FIXED: Ensure proper datetime format
        timestamp_str = self.event_timestamp.isoformat() if hasattr(self.event_timestamp, 'isoformat') else str(self.event_timestamp)
        
        # ✅ FIXED: Match server EventSubmissionRequest schema exactly
        data = {
            'agent_id': str(self.agent_id),
            'event_type': str(event_type_value),
            'event_action': str(event_action_value),
            'event_timestamp': timestamp_str,
            'severity': str(self.severity),
            
            # Process fields - match server schema
            'process_id': int(self.process_id) if self.process_id is not None else None,
            'process_name': str(self.process_name) if self.process_name else None,
            'process_path': str(self.process_path) if self.process_path else None,
            'command_line': str(self.command_line) if self.command_line else None,
            'parent_pid': int(self.parent_pid) if self.parent_pid is not None else None,
            'parent_process_name': str(self.parent_process_name) if self.parent_process_name else None,
            'process_user': str(self.process_user) if self.process_user else None,
            'process_hash': str(self.process_hash) if self.process_hash else None,
            
            # File fields - match server schema
            'file_path': str(self.file_path) if self.file_path else None,
            'file_name': str(self.file_name) if self.file_name else None,
            'file_size': int(self.file_size) if self.file_size is not None else None,
            'file_hash': str(self.file_hash) if self.file_hash else None,
            'file_extension': str(self.file_extension) if self.file_extension else None,
            'file_operation': str(self.file_operation) if self.file_operation else str(event_action_value),
            
            # Network fields - match server schema
            'source_ip': str(self.source_ip) if self.source_ip else None,
            'destination_ip': str(self.destination_ip) if self.destination_ip else None,
            'source_port': int(self.source_port) if self.source_port is not None else None,
            'destination_port': int(self.destination_port) if self.destination_port is not None else None,
            'protocol': str(self.protocol) if self.protocol else None,
            'direction': str(self.direction) if self.direction else None,
            
            # Registry fields - not used in Linux but required by schema
            'registry_key': str(self.registry_key) if self.registry_key else None,
            'registry_value_name': str(self.registry_value_name) if self.registry_value_name else None,
            'registry_value_data': str(self.registry_value_data) if self.registry_value_data else None,
            'registry_operation': str(self.registry_operation) if self.registry_operation else None,
            
            # Authentication fields - match server schema
            'login_user': str(self.login_user) if self.login_user else None,
            'login_type': str(self.login_type) if self.login_type else None,
            'login_result': str(self.login_result) if self.login_result else None,
                
                # Raw event data
            'raw_event_data': self.raw_event_data if self.raw_event_data else {}
        }
        
        # ✅ FIXED: Remove None values but keep required fields
        cleaned_data = {}
        for k, v in data.items():
            if v is not None or k in ['agent_id', 'event_type', 'event_action', 'event_timestamp', 'severity']:
                cleaned_data[k] = v
        
        return cleaned_data
    
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
        
        # Validate event_type (Linux - comprehensive list)
        valid_event_types = [
            "Process", "File", "Network", "Authentication", "System", 
            "Procfs", "Sysfs", "Sysctl", "Kernel", "Container_Security",
            "Service_Started", "Service_Stopped", "Service_Removed",
            "System_Event", "System_Performance", "System_Security"
        ]
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
        
        # Validate timestamp
        if not hasattr(event, 'event_timestamp') or event.event_timestamp is None:
            return False, "Missing required field: event_timestamp"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Validation error: {e}"