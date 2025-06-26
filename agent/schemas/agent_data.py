# agent/schemas/agent_data.py - FIXED Linux Agent Data Schemas
"""
Linux Agent Data Schemas - FIXED TO MATCH DATABASE SCHEMA
Define agent registration and communication structures compatible with EDR_System database
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
import platform
import os

@dataclass
class AgentRegistrationData:
    """
    Linux Agent Registration Data - FIXED TO MATCH DATABASE SCHEMA
    Maps to Agents table in EDR_System database
    """
    
    # REQUIRED FIELDS (matching Agents table constraints)
    hostname: str  # Maps to HostName (NVARCHAR(255) NOT NULL)
    ip_address: str  # Maps to IPAddress (NVARCHAR(45) NOT NULL) 
    operating_system: str  # Maps to OperatingSystem (NVARCHAR(100) NOT NULL)
    os_version: str  # Maps to OSVersion (NVARCHAR(100))
    architecture: str  # Maps to Architecture (NVARCHAR(20))
    agent_version: str  # Maps to AgentVersion (NVARCHAR(20) NOT NULL)
    
    # OPTIONAL FIELDS (matching database schema)
    mac_address: Optional[str] = None  # Maps to MACAddress (NVARCHAR(17))
    domain: Optional[str] = None  # Maps to Domain (NVARCHAR(100))
    install_path: Optional[str] = None  # Maps to InstallPath (NVARCHAR(500))
    
    # REQUIRED FIELDS with defaults
    status: str = "Active"  # Maps to Status (NVARCHAR(20) DEFAULT 'Active')
    cpu_usage: float = 0.0  # Maps to CPUUsage (DECIMAL(5,2) DEFAULT 0.0)
    memory_usage: float = 0.0  # Maps to MemoryUsage (DECIMAL(5,2) DEFAULT 0.0)
    disk_usage: float = 0.0  # Maps to DiskUsage (DECIMAL(5,2) DEFAULT 0.0)
    network_latency: int = 0  # Maps to NetworkLatency (INT DEFAULT 0)
    monitoring_enabled: bool = True  # Maps to MonitoringEnabled (BIT DEFAULT 1)
    
    # Linux-specific information (stored in metadata or separate fields)
    kernel_version: Optional[str] = None
    distribution: Optional[str] = None
    distribution_version: Optional[str] = None
    desktop_environment: Optional[str] = None
    
    # System information
    cpu_cores: Optional[int] = None
    total_memory: Optional[int] = None
    disk_space: Optional[int] = None
    
    # User information
    current_user: Optional[str] = None
    effective_user: Optional[str] = None
    user_groups: Optional[List[str]] = field(default_factory=list)
    
    # Security information
    has_root_privileges: bool = False
    selinux_enabled: Optional[bool] = None
    apparmor_enabled: Optional[bool] = None
    
    # Agent capabilities
    capabilities: Optional[List[str]] = field(default_factory=list)
    
    # Timestamps (will be set by database)
    registration_time: datetime = field(default_factory=datetime.now)
    
    # Additional metadata
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization to populate Linux-specific data and ensure database compatibility"""
        try:
            # Ensure metadata exists
            if not self.metadata:
                self.metadata = {}
            
            # Add platform identifier
            self.metadata['platform'] = 'linux'
            
            # Validate and normalize required fields for database constraints
            self._validate_and_normalize_fields()
            
            # Get Linux distribution info if not provided
            if not self.distribution:
                self._detect_linux_distribution()
            
            # Get kernel version if not provided
            if not self.kernel_version:
                self.kernel_version = platform.release()
            
            # Check root privileges
            self.has_root_privileges = os.geteuid() == 0
            
            # Get current user info
            if not self.current_user:
                self._get_user_info()
            
            # Get user groups
            if not self.user_groups:
                self._get_user_groups()
            
            # Check security modules
            if self.selinux_enabled is None:
                self.selinux_enabled = os.path.exists('/sys/fs/selinux')
            
            if self.apparmor_enabled is None:
                self.apparmor_enabled = os.path.exists('/sys/kernel/security/apparmor')
            
            # Detect desktop environment
            if not self.desktop_environment:
                self.desktop_environment = self._detect_desktop_environment()
            
            # Set default capabilities for Linux
            if not self.capabilities:
                self.capabilities = self._get_linux_capabilities()
            
            # Add system information to metadata
            self.metadata.update({
                'registration_timestamp': self.registration_time.isoformat(),
                'platform_details': {
                    'kernel': self.kernel_version,
                    'distribution': self.distribution,
                    'architecture': self.architecture,
                    'desktop_environment': self.desktop_environment
                },
                'security_features': {
                    'has_root': self.has_root_privileges,
                    'selinux': self.selinux_enabled,
                    'apparmor': self.apparmor_enabled
                },
                'user_context': {
                    'current_user': self.current_user,
                    'effective_user': self.effective_user,
                    'groups': self.user_groups
                }
            })
            
        except Exception as e:
            # Ensure metadata exists even if population fails
            if not self.metadata:
                self.metadata = {'error': str(e), 'platform': 'linux'}
    
    def _validate_and_normalize_fields(self):
        """Validate and normalize fields for database constraints"""
        try:
            # Validate hostname length (max 255 chars)
            if len(self.hostname) > 255:
                self.hostname = self.hostname[:255]
            
            # Validate IP address format
            if not self._is_valid_ip(self.ip_address):
                # Try to get a valid IP
                self.ip_address = self._get_fallback_ip()
            
            # Validate operating system length (max 100 chars)
            if len(self.operating_system) > 100:
                self.operating_system = self.operating_system[:100]
            
            # Validate OS version length (max 100 chars)
            if self.os_version and len(self.os_version) > 100:
                self.os_version = self.os_version[:100]
            
            # Validate architecture length (max 20 chars)
            if len(self.architecture) > 20:
                self.architecture = self.architecture[:20]
            
            # Validate agent version length (max 20 chars)
            if len(self.agent_version) > 20:
                self.agent_version = self.agent_version[:20]
            
            # Validate MAC address format and length (max 17 chars)
            if self.mac_address:
                if len(self.mac_address) > 17:
                    self.mac_address = self.mac_address[:17]
                if not self._is_valid_mac(self.mac_address):
                    self.mac_address = None
            
            # Validate domain length (max 100 chars)
            if self.domain and len(self.domain) > 100:
                self.domain = self.domain[:100]
            
            # Validate install path length (max 500 chars)
            if self.install_path and len(self.install_path) > 500:
                self.install_path = self.install_path[:500]
            
            # Validate status
            valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
            if self.status not in valid_statuses:
                self.status = 'Active'
            
            # Validate CPU usage (0-100)
            self.cpu_usage = max(0.0, min(100.0, self.cpu_usage))
            
            # Validate memory usage (0-100)
            self.memory_usage = max(0.0, min(100.0, self.memory_usage))
            
            # Validate disk usage (0-100)
            self.disk_usage = max(0.0, min(100.0, self.disk_usage))
            
            # Validate network latency (>= 0)
            self.network_latency = max(0, self.network_latency)
            
        except Exception as e:
            # Set safe defaults if validation fails
            if not hasattr(self, 'hostname') or not self.hostname:
                self.hostname = 'unknown-linux-host'
            if not hasattr(self, 'ip_address') or not self.ip_address:
                self.ip_address = '127.0.0.1'
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def _is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        try:
            import re
            pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            
            return bool(re.match(pattern, mac))
        except:
            return False
    
    def _get_fallback_ip(self) -> str:
        """Get fallback IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def _detect_linux_distribution(self):
        """Detect Linux distribution"""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('NAME='):
                        self.distribution = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION='):
                        self.distribution_version = line.split('=')[1].strip().strip('"')
        except:
            self.distribution = 'Unknown Linux'
            self.distribution_version = 'Unknown'
    
    def _get_user_info(self):
        """Get current user information"""
        try:
            import pwd
            self.current_user = pwd.getpwuid(os.getuid()).pw_name
            self.effective_user = pwd.getpwuid(os.geteuid()).pw_name
        except:
            self.current_user = 'unknown'
            self.effective_user = 'unknown'
    
    def _get_user_groups(self):
        """Get user groups"""
        try:
            import grp
            self.user_groups = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]
        except:
            self.user_groups = []
    
    def _detect_desktop_environment(self) -> str:
        """Detect Linux desktop environment"""
        try:
            # Check environment variables
            desktop_vars = [
                'XDG_CURRENT_DESKTOP',
                'DESKTOP_SESSION',
                'XDG_SESSION_DESKTOP'
            ]
            
            for var in desktop_vars:
                value = os.environ.get(var, '').lower()
                if value:
                    if 'gnome' in value:
                        return 'GNOME'
                    elif 'kde' in value or 'plasma' in value:
                        return 'KDE'
                    elif 'xfce' in value:
                        return 'XFCE'
                    elif 'mate' in value:
                        return 'MATE'
                    elif 'cinnamon' in value:
                        return 'Cinnamon'
                    elif 'unity' in value:
                        return 'Unity'
                    elif 'lxde' in value:
                        return 'LXDE'
                    else:
                        return value.upper()
            
            # Check for X11 or Wayland
            if os.environ.get('WAYLAND_DISPLAY'):
                return 'Wayland'
            elif os.environ.get('DISPLAY'):
                return 'X11'
            
            return 'Console'
            
        except Exception:
            return 'Unknown'
    
    def _get_linux_capabilities(self) -> List[str]:
        """Get Linux agent capabilities"""
        capabilities = [
            'process_monitoring',
            'file_monitoring',
            'network_monitoring',
            'authentication_monitoring',
            'system_monitoring'
        ]
        
        # Add capabilities based on privileges
        if self.has_root_privileges:
            capabilities.extend([
                'kernel_monitoring',
                'audit_monitoring',
                'container_monitoring',
                'service_monitoring'
            ])
        
        # Add capabilities based on available tools
        try:
            import subprocess
            
            # Check for inotify support
            if os.path.exists('/proc/sys/fs/inotify'):
                capabilities.append('inotify_monitoring')
            
            # Check for audit support
            if os.path.exists('/var/log/audit'):
                capabilities.append('audit_log_access')
            
            # Check for systemd
            result = subprocess.run(['which', 'systemctl'], capture_output=True)
            if result.returncode == 0:
                capabilities.append('systemd_monitoring')
            
            # Check for Docker
            result = subprocess.run(['which', 'docker'], capture_output=True)
            if result.returncode == 0:
                capabilities.append('docker_monitoring')
            
            # Check for Podman
            result = subprocess.run(['which', 'podman'], capture_output=True)
            if result.returncode == 0:
                capabilities.append('podman_monitoring')
                
        except:
            pass
        
        return capabilities
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database insertion (matching Agents table schema)"""
        try:
            # Create dictionary with exact database field names
            data = {
                # REQUIRED fields
                'HostName': self.hostname,
                'IPAddress': self.ip_address,
                'OperatingSystem': self.operating_system,
                'OSVersion': self.os_version,
                'Architecture': self.architecture,
                'AgentVersion': self.agent_version,
                
                # OPTIONAL fields
                'MACAddress': self.mac_address,
                'Domain': self.domain,
                'InstallPath': self.install_path,
                
                # STATUS and METRICS fields
                'Status': self.status,
                'CPUUsage': self.cpu_usage,
                'MemoryUsage': self.memory_usage,
                'DiskUsage': self.disk_usage,
                'NetworkLatency': self.network_latency,
                'MonitoringEnabled': self.monitoring_enabled,
                
                # TIMESTAMPS (database will set CreatedAt and UpdatedAt)
                'LastHeartbeat': datetime.now(),
                'FirstSeen': self.registration_time,
                
                # METADATA as JSON string for any additional data
                'Metadata': json.dumps(self.metadata, default=str) if self.metadata else None
            }
            
            # Remove None values for optional fields
            return {k: v for k, v in data.items() if v is not None}
            
        except Exception as e:
            return {
                'error': str(e), 
                'HostName': self.hostname or 'unknown',
                'IPAddress': self.ip_address or '127.0.0.1',
                'OperatingSystem': self.operating_system or 'Linux Unknown',
                'AgentVersion': self.agent_version or '2.1.0-Linux',
                'Status': 'Active'
            }

@dataclass
class AgentHeartbeatData:
    """
    Linux Agent Heartbeat Data - FIXED TO MATCH DATABASE EXPECTATIONS
    Used for regular status updates to server
    """
    
    # Basic information (not sent, used for identification)
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    
    # STATUS and PERFORMANCE METRICS (matching Agents table update fields)
    status: str = "Active"  # Maps to Status
    cpu_usage: float = 0.0  # Maps to CPUUsage
    memory_usage: float = 0.0  # Maps to MemoryUsage
    disk_usage: float = 0.0  # Maps to DiskUsage
    network_latency: int = 0  # Maps to NetworkLatency
    
    # TIMESTAMP
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # SYSTEM UPTIME
    uptime: Optional[float] = None
    agent_uptime: Optional[float] = None
    
    # COLLECTOR STATUS
    collector_status: Optional[Dict[str, str]] = field(default_factory=dict)
    
    # EVENT STATISTICS
    events_collected: int = 0
    events_sent: int = 0
    events_failed: int = 0
    alerts_received: int = 0
    
    # LINUX-SPECIFIC METRICS
    load_average: Optional[List[float]] = field(default_factory=list)
    memory_details: Optional[Dict[str, int]] = field(default_factory=dict)
    disk_details: Optional[Dict[str, Any]] = field(default_factory=dict)
    network_details: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    # PROCESS INFORMATION
    active_processes: int = 0
    agent_process_id: Optional[int] = None
    
    # SECURITY STATUS
    security_status: str = "Normal"
    threat_level: str = "Low"
    
    # ADDITIONAL METADATA
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization to collect Linux system metrics"""
        try:
            # Ensure metadata exists
            if not self.metadata:
                self.metadata = {}
            
            # Add platform identifier
            self.metadata['platform'] = 'linux'
            
            # Validate status
            valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
            if self.status not in valid_statuses:
                self.status = 'Active'
            
            # Validate metrics ranges
            self.cpu_usage = max(0.0, min(100.0, self.cpu_usage))
            self.memory_usage = max(0.0, min(100.0, self.memory_usage))
            self.disk_usage = max(0.0, min(100.0, self.disk_usage))
            self.network_latency = max(0, self.network_latency)
            
            # Get system uptime if not provided
            if self.uptime is None:
                self._get_system_uptime()
            
            # Get load average if not provided
            if not self.load_average:
                self._get_load_average()
            
            # Get memory details if not provided
            if not self.memory_details:
                self._get_memory_details()
            
            # Get disk details if not provided
            if not self.disk_details:
                self._get_disk_details()
            
            # Get network details if not provided
            if not self.network_details:
                self._get_network_details()
            
            # Get process count if not provided
            if self.active_processes == 0:
                self._get_process_count()
            
            # Get agent process ID if not provided
            if self.agent_process_id is None:
                self.agent_process_id = os.getpid()
            
            # Update metadata with system information
            self.metadata.update({
                'heartbeat_timestamp': self.timestamp,
                'system_metrics': {
                    'load_avg_1min': self.load_average[0] if self.load_average else 0,
                    'load_avg_5min': self.load_average[1] if len(self.load_average) > 1 else 0,
                    'load_avg_15min': self.load_average[2] if len(self.load_average) > 2 else 0,
                    'active_processes': self.active_processes,
                    'agent_pid': self.agent_process_id
                },
                'collector_status_summary': {
                    'total_collectors': len(self.collector_status),
                    'running_collectors': sum(1 for status in self.collector_status.values() if status == 'running'),
                    'failed_collectors': sum(1 for status in self.collector_status.values() if status == 'failed')
                }
            })
            
        except Exception as e:
            if not self.metadata:
                self.metadata = {'error': str(e), 'platform': 'linux'}
    
    def _get_system_uptime(self):
        """Get system uptime"""
        try:
            import psutil
            import time
            self.uptime = time.time() - psutil.boot_time()
        except:
            try:
                with open('/proc/uptime', 'r') as f:
                    self.uptime = float(f.read().split()[0])
            except:
                pass
    
    def _get_load_average(self):
        """Get load average"""
        try:
            self.load_average = list(os.getloadavg())
        except:
            pass
    
    def _get_memory_details(self):
        """Get memory details"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            self.memory_details = {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'free': memory.free,
                'buffers': getattr(memory, 'buffers', 0),
                'cached': getattr(memory, 'cached', 0)
            }
        except:
            pass
    
    def _get_disk_details(self):
        """Get disk details"""
        try:
            import psutil
            disk = psutil.disk_usage('/')
            self.disk_details = {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free
            }
        except:
            pass
    
    def _get_network_details(self):
        """Get network details"""
        try:
            import psutil
            net_io = psutil.net_io_counters()
            self.network_details = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except:
            pass
    
    def _get_process_count(self):
        """Get process count"""
        try:
            import psutil
            self.active_processes = len(psutil.pids())
        except:
            try:
                self.active_processes = len(os.listdir('/proc'))
            except:
                pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for heartbeat API (matching server expectations)"""
        try:
            # Create dictionary with database-compatible field names
            data = {
                # STATUS and METRICS for Agents table update
                'Status': self.status,
                'CPUUsage': self.cpu_usage,
                'MemoryUsage': self.memory_usage,
                'DiskUsage': self.disk_usage,
                'NetworkLatency': self.network_latency,
                
                # ADDITIONAL LINUX METRICS
                'Platform': 'linux',
                'Uptime': self.uptime,
                'LoadAverage': self.load_average,
                'MemoryDetails': self.memory_details,
                'DiskDetails': self.disk_details,
                'NetworkDetails': self.network_details,
                'ActiveProcesses': self.active_processes,
                'CollectorStatus': self.collector_status,
                'EventsCollected': self.events_collected,
                'EventsSent': self.events_sent,
                'EventsFailed': self.events_failed,
                'AlertsReceived': self.alerts_received,
                'SecurityStatus': self.security_status,
                'ThreatLevel': self.threat_level,
                'AgentProcessID': self.agent_process_id,
                'Timestamp': self.timestamp,
                'Metadata': self.metadata
            }
            
            # Remove None values
            return {k: v for k, v in data.items() if v is not None}
            
        except Exception as e:
            return {
                'error': str(e), 
                'Status': self.status,
                'Platform': 'linux',
                'Timestamp': self.timestamp
            }

# Utility functions for agent data handling
def create_linux_registration_data(hostname: str, ip_address: str, **kwargs) -> AgentRegistrationData:
    """Create Linux agent registration data with defaults"""
    try:
        # Get system information
        os_info = f"Linux {platform.system()} {platform.release()}"
        
        return AgentRegistrationData(
            hostname=hostname,
            ip_address=ip_address,
            operating_system=os_info,
            os_version=platform.release(),
            architecture=platform.machine(),
            agent_version="2.1.0-Linux",
            **kwargs
        )
    except Exception as e:
        # Return minimal data on error
        return AgentRegistrationData(
            hostname=hostname or "unknown",
            ip_address=ip_address or "127.0.0.1",
            operating_system="Linux Unknown",
            os_version="Unknown",
            architecture="Unknown",
            agent_version="2.1.0-Linux"
        )

def create_linux_heartbeat_data(agent_id: str = None, **kwargs) -> AgentHeartbeatData:
    """Create Linux agent heartbeat data with system metrics"""
    try:
        # Get current system metrics
        cpu_usage = 0.0
        memory_usage = 0.0
        disk_usage = 0.0
        
        try:
            import psutil
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            disk = psutil.disk_usage('/')
            disk_usage = disk.percent
        except ImportError:
            pass
        
        return AgentHeartbeatData(
            agent_id=agent_id,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            disk_usage=disk_usage,
            **kwargs
        )
    except Exception as e:
        # Return minimal heartbeat on error
        return AgentHeartbeatData(
            agent_id=agent_id,
            status="Error",
            metadata={'error': str(e)}
        )

def validate_agent_registration_data(data: AgentRegistrationData) -> tuple[bool, str]:
    """Validate agent registration data for database compatibility"""
    try:
        # Check required fields
        if not data.hostname:
            return False, "Missing hostname"
        
        if not data.ip_address:
            return False, "Missing IP address"
        
        if not data.operating_system:
            return False, "Missing operating system"
        
        if not data.agent_version:
            return False, "Missing agent version"
        
        # Validate field lengths for database constraints
        if len(data.hostname) > 255:
            return False, "Hostname too long (max 255 chars)"
        
        if len(data.ip_address) > 45:
            return False, "IP address too long (max 45 chars)"
        
        if len(data.operating_system) > 100:
            return False, "Operating system too long (max 100 chars)"
        
        if data.os_version and len(data.os_version) > 100:
            return False, "OS version too long (max 100 chars)"
        
        if len(data.architecture) > 20:
            return False, "Architecture too long (max 20 chars)"
        
        if len(data.agent_version) > 20:
            return False, "Agent version too long (max 20 chars)"
        
        if data.mac_address and len(data.mac_address) > 17:
            return False, "MAC address too long (max 17 chars)"
        
        if data.domain and len(data.domain) > 100:
            return False, "Domain too long (max 100 chars)"
        
        if data.install_path and len(data.install_path) > 500:
            return False, "Install path too long (max 500 chars)"
        
        # Validate IP address format
        try:
            parts = data.ip_address.split('.')
            if len(parts) != 4:
                return False, "Invalid IP address format"
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False, "Invalid IP address range"
        except:
            return False, "Invalid IP address"
        
        # Validate status
        valid_statuses = ['Active', 'Inactive', 'Error', 'Updating', 'Offline']
        if data.status not in valid_statuses:
            return False, f"Invalid status. Must be one of: {valid_statuses}"
        
        # Validate usage percentages
        if not (0 <= data.cpu_usage <= 100):
            return False, "CPU usage must be between 0 and 100"
        
        if not (0 <= data.memory_usage <= 100):
            return False, "Memory usage must be between 0 and 100"
        
        if not (0 <= data.disk_usage <= 100):
            return False, "Disk usage must be between 0 and 100"
        
        # Validate network latency
        if data.network_latency < 0:
            return False, "Network latency cannot be negative"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Validation error: {e}"

# Import json for metadata serialization
import json