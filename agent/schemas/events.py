# agent/schemas/events.py - FIXED Linux Event Schemas
"""
Linux Event Data Schemas - FIXED TO MATCH DATABASE SCHEMA
Compatible with EDR_System database structure and server expectations
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import logging

class EventAction(Enum):
    """Event actions matching database expectations"""
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

class EventSeverity(Enum):
    """Event severity levels matching database schema"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class EventData:
    """
    Linux Event Data Structure - FIXED TO MATCH DATABASE SCHEMA
    Maps to Events table in EDR_System database
    """
    
    # REQUIRED: Core event information matching database
    event_type: str  # Maps to EventType (Process, File, Network, Registry, Authentication, System)
    event_action: str  # Maps to EventAction  
    event_timestamp: datetime = field(default_factory=datetime.now)  # Maps to EventTimestamp
    severity: str = "Info"  # Maps to Severity
    
    # REQUIRED: Agent information
    agent_id: Optional[str] = None  # Maps to AgentID (REQUIRED)
    
    # Process information (Maps to database process fields)
    process_id: Optional[int] = None  # Maps to ProcessID
    process_name: Optional[str] = None  # Maps to ProcessName
    process_path: Optional[str] = None  # Maps to ProcessPath
    command_line: Optional[str] = None  # Maps to CommandLine
    parent_pid: Optional[int] = None  # Maps to ParentPID
    parent_process_name: Optional[str] = None  # Maps to ParentProcessName
    process_user: Optional[str] = None  # Maps to ProcessUser
    process_hash: Optional[str] = None  # Maps to ProcessHash
    
    # File information (Maps to database file fields)
    file_path: Optional[str] = None  # Maps to FilePath
    file_name: Optional[str] = None  # Maps to FileName
    file_size: Optional[int] = None  # Maps to FileSize
    file_hash: Optional[str] = None  # Maps to FileHash
    file_extension: Optional[str] = None  # Maps to FileExtension
    file_operation: Optional[str] = None  # Maps to FileOperation
    
    # Network information (Maps to database network fields)
    source_ip: Optional[str] = None  # Maps to SourceIP
    destination_ip: Optional[str] = None  # Maps to DestinationIP
    source_port: Optional[int] = None  # Maps to SourcePort
    destination_port: Optional[int] = None  # Maps to DestinationPort
    protocol: Optional[str] = None  # Maps to Protocol
    direction: Optional[str] = None  # Maps to Direction
    
    # Registry information (kept for compatibility)
    registry_key: Optional[str] = None  # Maps to RegistryKey
    registry_value_name: Optional[str] = None  # Maps to RegistryValueName
    registry_value_data: Optional[str] = None  # Maps to RegistryValueData
    registry_operation: Optional[str] = None  # Maps to RegistryOperation
    
    # Authentication information (Maps to database auth fields)
    login_user: Optional[str] = None  # Maps to LoginUser
    login_type: Optional[str] = None  # Maps to LoginType
    login_result: Optional[str] = None  # Maps to LoginResult
    
    # Detection status (Maps to database detection fields)
    threat_level: str = "None"  # Maps to ThreatLevel
    risk_score: int = 0  # Maps to RiskScore
    analyzed: bool = False  # Maps to Analyzed
    analyzed_at: Optional[datetime] = None  # Maps to AnalyzedAt
    
    # Raw event data (Maps to RawEventData)
    raw_event_data: Optional[str] = None  # Maps to RawEventData (NVARCHAR(MAX))
    
    # Additional Linux-specific fields (stored in raw_event_data)
    hostname: Optional[str] = None
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    network_usage: Optional[float] = None
    description: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing to ensure database compatibility"""
        # FIX: Validate agent_id immediately
        if not self.agent_id:
            # Don't raise error here, just log for debugging
            logger = logging.getLogger(__name__)
            logger.debug(f"EventData created without agent_id - Type: {self.event_type}, Action: {self.event_action}")
        # Ensure event_action is string value
        if hasattr(self.event_action, 'value'):
            self.event_action = self.event_action.value
        
        # Normalize severity to match database constraints
        severity_map = {
            'CRITICAL': 'Critical',
            'HIGH': 'High', 
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFO': 'Info',
            'INFORMATION': 'Info'
        }
        self.severity = severity_map.get(self.severity.upper(), self.severity)
        
        # Ensure threat_level matches database constraints
        threat_level_map = {
            'NONE': 'None',
            'SUSPICIOUS': 'Suspicious', 
            'MALICIOUS': 'Malicious'
        }
        self.threat_level = threat_level_map.get(self.threat_level.upper(), 'None')
        
        # Ensure risk_score is within valid range
        self.risk_score = max(0, min(100, self.risk_score))
        
        # Generate description if not provided
        if not self.description:
            self.description = self._generate_description()
        
        # Prepare raw_event_data as JSON string
        self._prepare_raw_event_data()
    
    def _generate_description(self) -> str:
        """Generate event description"""
        try:
            if self.event_type == "Process":
                return f"Linux Process {self.event_action}: {self.process_name or 'Unknown'}"
            elif self.event_type == "File":
                return f"Linux File {self.event_action}: {self.file_name or self.file_path or 'Unknown'}"
            elif self.event_type == "Network":
                if self.destination_ip:
                    return f"Linux Network {self.event_action}: {self.destination_ip}:{self.destination_port or 0}"
                return f"Linux Network {self.event_action}"
            elif self.event_type == "Authentication":
                return f"Linux Auth {self.event_action}: {self.login_user or 'Unknown'}"
            elif self.event_type == "System":
                return f"Linux System {self.event_action}"
            else:
                return f"Linux {self.event_type} Event: {self.event_action}"
        except Exception:
            return f"Linux Event: {self.event_type} - {self.event_action}"
    
    def _prepare_raw_event_data(self):
        """Prepare raw_event_data as JSON string for database storage - FIXED"""
        try:
            import json
            # If raw_event_data is already a dict, use it
            if isinstance(self.raw_event_data, dict):
                raw_data = self.raw_event_data.copy()
            elif isinstance(self.raw_event_data, str):
                try:
                    raw_data = json.loads(self.raw_event_data)
                except:
                    raw_data = {'original_data': self.raw_event_data}
            else:
                raw_data = {}
            raw_data.update({
                'platform': 'linux',
                'event_timestamp': self.event_timestamp.isoformat(),
                'description': self.description
            })
            optional_fields = [
                'hostname', 'cpu_usage', 'memory_usage', 'disk_usage',
                'network_usage', 'process_uid', 'process_gid',
                'process_effective_uid', 'process_effective_gid',
                'process_session_id', 'process_terminal',
                'process_working_directory', 'process_environment',
                'file_permissions', 'file_owner', 'file_group',
                'file_inode', 'file_device', 'file_mount_point',
                'file_type', 'network_interface', 'network_namespace',
                'connection_state', 'bytes_sent', 'bytes_received',
                'login_source_ip', 'login_terminal', 'login_session_id'
            ]
            for field in optional_fields:
                value = getattr(self, field, None)
                if value is not None:
                    raw_data[field] = value
            self.raw_event_data = json.dumps(raw_data, default=str)
        except Exception as e:
            self.raw_event_data = f'{{"platform": "linux", "error": "{str(e)}"}}'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API submission"""
        try:
            # FIX: Validate agent_id before serialization
            if not self.agent_id:
                return {'error': 'Event missing required agent_id field'}
            data = {
                # REQUIRED fields (snake_case)
                'agent_id': self.agent_id,
                'event_type': self.event_type,
                'event_action': self.event_action,
                'event_timestamp': self.event_timestamp.isoformat() if self.event_timestamp else None,
                'severity': self.severity,
                # Process fields (optional)
                'process_id': self.process_id,
                'process_name': self.process_name,
                'process_path': self.process_path,
                'command_line': self.command_line,
                'parent_pid': self.parent_pid,
                'parent_process_name': self.parent_process_name,
                'process_user': self.process_user,
                'process_hash': self.process_hash,
                # File fields (optional)
                'file_path': self.file_path,
                'file_name': self.file_name,
                'file_size': self.file_size,
                'file_hash': self.file_hash,
                'file_extension': self.file_extension,
                'file_operation': self.file_operation,
                # Network fields (optional)
                'source_ip': self.source_ip,
                'destination_ip': self.destination_ip,
                'source_port': self.source_port,
                'destination_port': self.destination_port,
                'protocol': self.protocol,
                'connection_status': self.connection_status,
                # Authentication fields (optional)
                'user_name': self.user_name,
                'login_status': self.login_status,
                'authentication_method': self.authentication_method,
                # System fields (optional)
                'system_event': self.system_event,
                'system_message': self.system_message,
                # Threat detection fields
                'threat_level': self.threat_level,
                'risk_score': self.risk_score,
                'analyzed': self.analyzed,
                # Raw event data
                'raw_event_data': self.raw_event_data
            }
            # Remove None values
            return {k: v for k, v in data.items() if v is not None}
        except Exception as e:
            return {'error': f'Event serialization failed: {str(e)}'}
    
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
                raw_event_data=f'{{"error": "{str(e)}", "original_data": {str(data)}}}'
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
    
    def is_critical(self) -> bool:
        """Check if event is critical"""
        return self.severity == 'Critical' or self.risk_score >= 90

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
        
        # Validate event_type
        valid_event_types = ["Process", "File", "Network", "Registry", "Authentication", "System"]
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