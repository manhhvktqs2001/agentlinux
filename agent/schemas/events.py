# agent/schemas/events.py - Linux Event Schemas
"""
Linux Event Data Schemas - Define event structures for Linux EDR monitoring
Optimized for Linux platform-specific events and monitoring capabilities
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum

class EventAction(Enum):
    """Linux-compatible event actions"""
    # Process actions
    START = "Process_Start"
    STOP = "Process_Stop" 
    CREATE = "Process_Create"
    TERMINATE = "Process_Terminate"
    
    # File actions
    READ = "File_Read"
    WRITE = "File_Write"
    DELETE = "File_Delete"
    MODIFY = "File_Modify"
    RENAME = "File_Rename"
    COPY = "File_Copy"
    MOVE = "File_Move"
    
    # Network actions
    CONNECT = "Network_Connect"
    DISCONNECT = "Network_Disconnect"
    LISTEN = "Network_Listen"
    SEND = "Network_Send"
    RECEIVE = "Network_Receive"
    
    # Authentication actions (Linux-specific)
    LOGIN = "Auth_Login"
    LOGOUT = "Auth_Logout"
    LOGIN_FAILED = "Auth_Login_Failed"
    SUDO = "Auth_Sudo"
    SU = "Auth_Su"
    SSH_LOGIN = "Auth_SSH_Login"
    
    # System actions (Linux-specific)
    SERVICE_START = "System_Service_Start"
    SERVICE_STOP = "System_Service_Stop"
    MOUNT = "System_Mount"
    UNMOUNT = "System_Unmount"
    MODULE_LOAD = "System_Module_Load"
    MODULE_UNLOAD = "System_Module_Unload"
    
    # Security actions
    SUSPICIOUS_ACTIVITY = "Security_Suspicious"
    THREAT_DETECTED = "Security_Threat"
    MALWARE_DETECTED = "Security_Malware"
    
    # General actions
    ACCESS = "Access"
    EXECUTE = "Execute"
    LOAD = "Load"
    UNLOAD = "Unload"
    RESOURCE_USAGE = "Resource_Usage"

class EventSeverity(Enum):
    """Event severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

@dataclass
class EventData:
    """Linux Event Data Structure - Comprehensive event information"""
    
    # Core event information
    event_type: str
    event_action: EventAction
    event_timestamp: datetime = field(default_factory=datetime.now)
    severity: str = "Info"
    
    # Agent information
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    
    # Process information
    process_id: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    process_user: Optional[str] = None
    process_hash: Optional[str] = None
    
    # Linux-specific process information
    process_uid: Optional[int] = None
    process_gid: Optional[int] = None
    process_effective_uid: Optional[int] = None
    process_effective_gid: Optional[int] = None
    process_session_id: Optional[int] = None
    process_terminal: Optional[str] = None
    process_working_directory: Optional[str] = None
    process_environment: Optional[Dict[str, str]] = None
    
    # File information
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    file_extension: Optional[str] = None
    file_operation: Optional[str] = None
    
    # Linux-specific file information
    file_permissions: Optional[str] = None
    file_owner: Optional[str] = None
    file_group: Optional[str] = None
    file_inode: Optional[int] = None
    file_device: Optional[str] = None
    file_mount_point: Optional[str] = None
    file_type: Optional[str] = None  # regular, directory, symlink, etc.
    
    # Network information
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    
    # Linux-specific network information
    network_interface: Optional[str] = None
    network_namespace: Optional[str] = None
    connection_state: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    
    # Registry information (not applicable for Linux, kept for compatibility)
    registry_key: Optional[str] = None
    registry_value_name: Optional[str] = None
    registry_value_data: Optional[str] = None
    registry_operation: Optional[str] = None
    
    # Authentication information (Linux-specific)
    login_user: Optional[str] = None
    login_type: Optional[str] = None  # console, ssh, su, sudo
    login_result: Optional[str] = None  # success, failure
    login_source_ip: Optional[str] = None
    login_terminal: Optional[str] = None
    login_session_id: Optional[str] = None
    
    # System information (Linux-specific)
    system_call: Optional[str] = None
    system_call_args: Optional[List[str]] = None
    kernel_module: Optional[str] = None
    service_name: Optional[str] = None
    service_state: Optional[str] = None
    mount_source: Optional[str] = None
    mount_target: Optional[str] = None
    mount_filesystem: Optional[str] = None
    
    # Resource usage information
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    network_usage: Optional[float] = None
    
    # Container information (Linux-specific)
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    container_image: Optional[str] = None
    container_runtime: Optional[str] = None  # docker, podman, etc.
    
    # Audit information (Linux-specific)
    audit_record_type: Optional[str] = None
    audit_record_id: Optional[str] = None
    audit_user: Optional[str] = None
    audit_success: Optional[bool] = None
    
    # Description and metadata
    description: Optional[str] = None
    tags: Optional[List[str]] = field(default_factory=list)
    
    # Raw event data (platform-specific)
    raw_event_data: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing for Linux events"""
        # Ensure raw_event_data is a dict
        if self.raw_event_data is None:
            self.raw_event_data = {}
        
        # Add platform identifier
        self.raw_event_data['platform'] = 'linux'
        
        # Add timestamp if not present
        if 'event_timestamp' not in self.raw_event_data:
            self.raw_event_data['event_timestamp'] = self.event_timestamp.isoformat()
        
        # Normalize severity
        severity_map = {
            'CRITICAL': 'Critical',
            'HIGH': 'High', 
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFO': 'Info'
        }
        self.severity = severity_map.get(self.severity.upper(), self.severity)
        
        # Generate description if not provided
        if not self.description:
            self.description = self._generate_description()
    
    def _generate_description(self) -> str:
        """Generate event description for Linux events"""
        try:
            if self.event_type == "Process":
                action_name = self.event_action.value.split('_')[-1]
                return f"Linux Process {action_name}: {self.process_name or 'Unknown'}"
            
            elif self.event_type == "File":
                action_name = self.event_action.value.split('_')[-1]
                return f"Linux File {action_name}: {self.file_name or self.file_path or 'Unknown'}"
            
            elif self.event_type == "Network":
                action_name = self.event_action.value.split('_')[-1]
                if self.destination_ip:
                    return f"Linux Network {action_name}: {self.destination_ip}:{self.destination_port or 0}"
                return f"Linux Network {action_name}"
            
            elif self.event_type == "Authentication":
                action_name = self.event_action.value.split('_')[-1]
                return f"Linux Auth {action_name}: {self.login_user or 'Unknown'}"
            
            elif self.event_type == "System":
                action_name = self.event_action.value.split('_')[-1]
                return f"Linux System {action_name}: {self.service_name or 'Unknown'}"
            
            else:
                return f"Linux {self.event_type} Event: {self.event_action.value}"
                
        except Exception:
            return f"Linux Event: {self.event_type} - {self.event_action}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for JSON serialization"""
        try:
            event_dict = {}
            
            for field_name, field_value in self.__dict__.items():
                if field_value is not None:
                    if isinstance(field_value, datetime):
                        event_dict[field_name] = field_value.isoformat()
                    elif isinstance(field_value, EventAction):
                        event_dict[field_name] = field_value.value
                    elif isinstance(field_value, (list, dict)):
                        event_dict[field_name] = field_value
                    else:
                        event_dict[field_name] = field_value
            
            return event_dict
            
        except Exception as e:
            return {
                'error': f'Serialization error: {e}',
                'event_type': self.event_type,
                'timestamp': datetime.now().isoformat()
            }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EventData':
        """Create EventData from dictionary"""
        try:
            # Handle datetime conversion
            if 'event_timestamp' in data and isinstance(data['event_timestamp'], str):
                data['event_timestamp'] = datetime.fromisoformat(data['event_timestamp'].replace('Z', '+00:00'))
            
            # Handle EventAction conversion
            if 'event_action' in data and isinstance(data['event_action'], str):
                try:
                    data['event_action'] = EventAction(data['event_action'])
                except ValueError:
                    # Default action if not found
                    data['event_action'] = EventAction.ACCESS
            
            return cls(**data)
            
        except Exception as e:
            # Return minimal event on error
            return cls(
                event_type="System",
                event_action=EventAction.ACCESS,
                description=f"Error creating event from dict: {e}",
                raw_event_data=data
            )
    
    def add_linux_context(self, context: Dict[str, Any]):
        """Add Linux-specific context to the event"""
        try:
            if 'raw_event_data' not in self.__dict__ or not self.raw_event_data:
                self.raw_event_data = {}
            
            # Add Linux context
            linux_context = {
                'linux_context': context,
                'platform': 'linux',
                'context_added': datetime.now().isoformat()
            }
            
            self.raw_event_data.update(linux_context)
            
        except Exception as e:
            # Silently handle context addition errors
            pass
    
    def set_threat_indicators(self, threat_score: int, threat_description: str = None):
        """Set threat indicators for the event"""
        try:
            if not self.raw_event_data:
                self.raw_event_data = {}
            
            self.raw_event_data['threat_score'] = min(max(threat_score, 0), 100)
            
            if threat_description:
                self.raw_event_data['threat_description'] = threat_description
            
            # Adjust severity based on threat score
            if threat_score >= 90:
                self.severity = "Critical"
            elif threat_score >= 70:
                self.severity = "High"
            elif threat_score >= 50:
                self.severity = "Medium"
            elif threat_score >= 30:
                self.severity = "Low"
            
        except Exception:
            pass
    
    def is_suspicious(self) -> bool:
        """Check if event has suspicious indicators"""
        try:
            # Check threat score
            threat_score = self.raw_event_data.get('threat_score', 0) if self.raw_event_data else 0
            if threat_score >= 50:
                return True
            
            # Check severity
            if self.severity in ['Critical', 'High']:
                return True
            
            # Check for suspicious processes
            if self.process_name:
                suspicious_processes = ['nc', 'netcat', 'bash -i', 'sh -i', 'python -c']
                for proc in suspicious_processes:
                    if proc in self.process_name.lower():
                        return True
            
            # Check for suspicious files
            if self.file_path:
                suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/']
                for path in suspicious_paths:
                    if path in self.file_path:
                        return True
            
            return False
            
        except Exception:
            return False
    
    def get_summary(self) -> str:
        """Get a brief summary of the event"""
        try:
            parts = [f"Linux {self.event_type}"]
            
            if self.process_name:
                parts.append(f"Process: {self.process_name}")
            
            if self.file_name:
                parts.append(f"File: {self.file_name}")
            
            if self.destination_ip:
                parts.append(f"Network: {self.destination_ip}")
            
            if self.login_user:
                parts.append(f"User: {self.login_user}")
            
            parts.append(f"Severity: {self.severity}")
            
            return " | ".join(parts)
            
        except Exception:
            return f"Linux Event: {self.event_type}"

@dataclass
class LinuxProcessEvent(EventData):
    """Linux-specific process event"""
    
    def __init__(self, **kwargs):
        super().__init__(event_type="Process", **kwargs)
    
    @classmethod
    def create_start_event(cls, pid: int, process_name: str, command_line: str = None, 
                          user: str = None, parent_pid: int = None) -> 'LinuxProcessEvent':
        """Create a process start event"""
        return cls(
            event_action=EventAction.START,
            process_id=pid,
            process_name=process_name,
            command_line=command_line,
            process_user=user,
            parent_pid=parent_pid,
            description=f"Linux Process Started: {process_name} (PID: {pid})"
        )
    
    @classmethod
    def create_stop_event(cls, pid: int, process_name: str, user: str = None) -> 'LinuxProcessEvent':
        """Create a process stop event"""
        return cls(
            event_action=EventAction.STOP,
            process_id=pid,
            process_name=process_name,
            process_user=user,
            description=f"Linux Process Stopped: {process_name} (PID: {pid})"
        )

@dataclass
class LinuxFileEvent(EventData):
    """Linux-specific file event"""
    
    def __init__(self, **kwargs):
        super().__init__(event_type="File", **kwargs)
    
    @classmethod
    def create_access_event(cls, file_path: str, operation: str, process_name: str = None,
                           user: str = None) -> 'LinuxFileEvent':
        """Create a file access event"""
        action_map = {
            'read': EventAction.READ,
            'write': EventAction.WRITE,
            'delete': EventAction.DELETE,
            'modify': EventAction.MODIFY,
            'create': EventAction.CREATE
        }
        
        action = action_map.get(operation.lower(), EventAction.ACCESS)
        file_name = file_path.split('/')[-1] if '/' in file_path else file_path
        
        return cls(
            event_action=action,
            file_path=file_path,
            file_name=file_name,
            file_operation=operation,
            process_name=process_name,
            process_user=user,
            description=f"Linux File {operation.title()}: {file_name}"
        )

@dataclass
class LinuxNetworkEvent(EventData):
    """Linux-specific network event"""
    
    def __init__(self, **kwargs):
        super().__init__(event_type="Network", **kwargs)
    
    @classmethod
    def create_connection_event(cls, source_ip: str, source_port: int, dest_ip: str, 
                               dest_port: int, protocol: str = "TCP", 
                               process_name: str = None) -> 'LinuxNetworkEvent':
        """Create a network connection event"""
        return cls(
            event_action=EventAction.CONNECT,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=dest_ip,
            destination_port=dest_port,
            protocol=protocol.upper(),
            process_name=process_name,
            direction="Outbound",
            description=f"Linux Network Connection: {source_ip}:{source_port} -> {dest_ip}:{dest_port}"
        )

@dataclass
class LinuxAuthEvent(EventData):
    """Linux-specific authentication event"""
    
    def __init__(self, **kwargs):
        super().__init__(event_type="Authentication", **kwargs)
    
    @classmethod
    def create_login_event(cls, user: str, login_type: str, result: str, 
                          source_ip: str = None, terminal: str = None) -> 'LinuxAuthEvent':
        """Create a login event"""
        action = EventAction.LOGIN if result.lower() == "success" else EventAction.LOGIN_FAILED
        severity = "Info" if result.lower() == "success" else "Medium"
        
        return cls(
            event_action=action,
            login_user=user,
            login_type=login_type,
            login_result=result,
            login_source_ip=source_ip,
            login_terminal=terminal,
            severity=severity,
            description=f"Linux {login_type.title()} Login: {user} - {result}"
        )
    
    @classmethod
    def create_sudo_event(cls, user: str, command: str, result: str) -> 'LinuxAuthEvent':
        """Create a sudo event"""
        return cls(
            event_action=EventAction.SUDO,
            login_user=user,
            login_type="sudo",
            login_result=result,
            command_line=command,
            severity="Medium" if result.lower() == "success" else "High",
            description=f"Linux Sudo: {user} executed '{command}' - {result}"
        )

@dataclass
class LinuxSystemEvent(EventData):
    """Linux-specific system event"""
    
    def __init__(self, **kwargs):
        super().__init__(event_type="System", **kwargs)
    
    @classmethod
    def create_service_event(cls, service_name: str, action: str, state: str = None) -> 'LinuxSystemEvent':
        """Create a service event"""
        action_map = {
            'start': EventAction.SERVICE_START,
            'stop': EventAction.SERVICE_STOP,
            'restart': EventAction.SERVICE_START
        }
        
        event_action = action_map.get(action.lower(), EventAction.ACCESS)
        
        return cls(
            event_action=event_action,
            service_name=service_name,
            service_state=state,
            description=f"Linux Service {action.title()}: {service_name}"
        )
    
    @classmethod
    def create_mount_event(cls, source: str, target: str, filesystem: str = None) -> 'LinuxSystemEvent':
        """Create a mount event"""
        return cls(
            event_action=EventAction.MOUNT,
            mount_source=source,
            mount_target=target,
            mount_filesystem=filesystem,
            description=f"Linux Mount: {source} -> {target}"
        )

# Event factory functions for easy event creation
def create_linux_process_event(pid: int, name: str, action: str = "start", **kwargs) -> LinuxProcessEvent:
    """Factory function to create Linux process events"""
    if action.lower() == "start":
        return LinuxProcessEvent.create_start_event(pid, name, **kwargs)
    else:
        return LinuxProcessEvent.create_stop_event(pid, name, **kwargs)

def create_linux_file_event(file_path: str, operation: str, **kwargs) -> LinuxFileEvent:
    """Factory function to create Linux file events"""
    return LinuxFileEvent.create_access_event(file_path, operation, **kwargs)

def create_linux_network_event(source_ip: str, source_port: int, dest_ip: str, 
                               dest_port: int, **kwargs) -> LinuxNetworkEvent:
    """Factory function to create Linux network events"""
    return LinuxNetworkEvent.create_connection_event(source_ip, source_port, dest_ip, dest_port, **kwargs)

def create_linux_auth_event(user: str, login_type: str, result: str, **kwargs) -> LinuxAuthEvent:
    """Factory function to create Linux authentication events"""
    return LinuxAuthEvent.create_login_event(user, login_type, result, **kwargs)

def create_linux_system_event(service_name: str, action: str, **kwargs) -> LinuxSystemEvent:
    """Factory function to create Linux system events"""
    return LinuxSystemEvent.create_service_event(service_name, action, **kwargs)

# Event validation functions
def validate_event_data(event: EventData) -> tuple[bool, str]:
    """Validate event data structure"""
    try:
        # Check required fields
        if not event.event_type:
            return False, "Missing event_type"
        
        if not event.event_action:
            return False, "Missing event_action"
        
        if not event.event_timestamp:
            return False, "Missing event_timestamp"
        
        # Validate event_action is proper enum
        if not isinstance(event.event_action, EventAction):
            return False, "Invalid event_action type"
        
        # Validate severity
        valid_severities = ["Critical", "High", "Medium", "Low", "Info"]
        if event.severity not in valid_severities:
            return False, f"Invalid severity: {event.severity}"
        
        # Type-specific validations
        if event.event_type == "Process":
            if not event.process_id and not event.process_name:
                return False, "Process events require process_id or process_name"
        
        elif event.event_type == "File":
            if not event.file_path and not event.file_name:
                return False, "File events require file_path or file_name"
        
        elif event.event_type == "Network":
            if not event.source_ip and not event.destination_ip:
                return False, "Network events require source_ip or destination_ip"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Validation error: {e}"

def normalize_event_data(event: EventData) -> EventData:
    """Normalize event data for consistency"""
    try:
        # Normalize severity
        if event.severity:
            severity_map = {
                'critical': 'Critical',
                'high': 'High',
                'medium': 'Medium', 
                'low': 'Low',
                'info': 'Info',
                'information': 'Info'
            }
            event.severity = severity_map.get(event.severity.lower(), event.severity)
        
        # Normalize process names
        if event.process_name:
            event.process_name = event.process_name.strip()
        
        # Normalize file paths
        if event.file_path:
            event.file_path = event.file_path.strip().replace('\\', '/')
        
        # Normalize IP addresses
        if event.source_ip:
            event.source_ip = event.source_ip.strip()
        if event.destination_ip:
            event.destination_ip = event.destination_ip.strip()
        
        # Ensure raw_event_data exists
        if not event.raw_event_data:
            event.raw_event_data = {}
        
        # Add platform identifier
        event.raw_event_data['platform'] = 'linux'
        
        return event
        
    except Exception as e:
        # Return original event if normalization fails
        return event