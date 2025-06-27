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
import json

@dataclass
class AgentRegistrationData:
    """
    FIXED: Linux Agent Registration Data - DATABASE COMPATIBLE
    Now includes ALL required fields for EDR_System database
    """
    
    # ✅ FIXED: Required fields matching database schema exactly
    hostname: str                    # Maps to HostName (REQUIRED)
    ip_address: str                 # Maps to IPAddress (REQUIRED)
    operating_system: str           # Maps to OperatingSystem (REQUIRED)
    os_version: str                # Maps to OSVersion (REQUIRED)
    architecture: str              # Maps to Architecture (REQUIRED)
    agent_version: str             # Maps to AgentVersion (REQUIRED)
    
    # ✅ FIXED: Optional fields with proper defaults
    mac_address: Optional[str] = None
    domain: Optional[str] = "local.linux"  # ✅ FIXED: Provide default
    install_path: Optional[str] = None
    status: str = "Active"
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: int = 0
    monitoring_enabled: bool = True
    
    # ✅ FIXED: Platform identifier 
    platform: str = "linux"
    
    # Linux-specific fields
    kernel_version: Optional[str] = None
    distribution: Optional[str] = None
    current_user: Optional[str] = None
    has_root_privileges: bool = False
    
    def __post_init__(self):
        """✅ FIXED: Enhanced post-initialization with proper validation"""
        try:
            # ✅ FIXED: Ensure hostname is always set
            if not self.hostname:
                self.hostname = platform.node() or "linux-edr-agent"
            
            # ✅ FIXED: Validate hostname length for database
            if len(self.hostname) > 255:
                self.hostname = self.hostname[:255]
            
            # ✅ FIXED: Ensure IP address is valid
            if not self.ip_address or not self._is_valid_ip(self.ip_address):
                self.ip_address = self._get_fallback_ip()
            
            # ✅ FIXED: Set Linux-specific information
            if not self.os_version:
                self.os_version = platform.release()
            
            if not self.architecture:
                self.architecture = platform.machine()
            
            if not self.operating_system:
                self.operating_system = f"Linux {platform.system()}"
            
            # ✅ FIXED: Detect distribution if not set
            if not self.distribution:
                self._detect_linux_distribution()
            
            # ✅ FIXED: Get current user info
            if not self.current_user:
                try:
                    import pwd
                    self.current_user = pwd.getpwuid(os.getuid()).pw_name
                except:
                    self.current_user = "unknown"
            
            # ✅ FIXED: Check root privileges
            self.has_root_privileges = os.geteuid() == 0
            
            # ✅ FIXED: Set default domain for Linux
            if not self.domain:
                self.domain = self._get_linux_domain()
            
        except Exception as e:
            # ✅ FIXED: Set safe defaults on error
            if not self.hostname:
                self.hostname = "linux-edr-agent"
            if not self.ip_address:
                self.ip_address = "127.0.0.1"
    
    def _is_valid_ip(self, ip: str) -> bool:
        """✅ FIXED: Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _get_fallback_ip(self) -> str:
        """✅ FIXED: Get fallback IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _detect_linux_distribution(self):
        """✅ FIXED: Detect Linux distribution"""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('NAME='):
                        self.distribution = line.split('=')[1].strip().strip('"')
                        break
        except:
            self.distribution = "Unknown Linux"
    
    def _get_linux_domain(self) -> str:
        """✅ FIXED: Get Linux domain"""
        try:
            import socket
            fqdn = socket.getfqdn()
            if '.' in fqdn and not fqdn.endswith('.localdomain'):
                return fqdn.split('.', 1)[1]
            return "local.linux"
        except:
            return "local.linux"
    
    def to_dict(self) -> Dict[str, Any]:
        """✅ FIXED: Convert to dictionary with ALL required fields"""
        return {
            # ✅ FIXED: ALL required database fields
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'operating_system': self.operating_system,
            'os_version': self.os_version,
            'architecture': self.architecture,
            'agent_version': self.agent_version,
            'mac_address': self.mac_address,
            'domain': self.domain,
            'install_path': self.install_path,
            'status': self.status,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'disk_usage': self.disk_usage,
            'network_latency': self.network_latency,
            'monitoring_enabled': self.monitoring_enabled,
            'platform': self.platform,
            'kernel_version': self.kernel_version,
            'distribution': self.distribution,
            'current_user': self.current_user,
            'has_root_privileges': self.has_root_privileges
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
                'hostname': self.hostname,  # Always include hostname for server validation
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