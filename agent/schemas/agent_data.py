# agent/schemas/agent_data.py - Linux Agent Data Schemas
"""
Linux Agent Data Schemas - Define agent registration and communication structures
Optimized for Linux platform with enhanced system information
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
import platform
import os

@dataclass
class AgentConfigurationData:
    """Linux Agent Configuration Data"""
    
    # Agent settings
    agent_id: str
    heartbeat_interval: int = 30
    event_batch_size: int = 100
    event_queue_size: int = 2000
    
    # Collection settings
    collect_processes: bool = True
    collect_files: bool = True
    collect_network: bool = True
    collect_authentication: bool = True
    collect_system_events: bool = True
    
    # Linux-specific collection settings
    collect_audit_logs: bool = True
    collect_syslog: bool = True
    collect_containers: bool = True
    monitor_systemd: bool = True
    use_inotify: bool = True
    
    # Performance settings
    max_cpu_usage: float = 25.0
    max_memory_usage: int = 512  # MB
    polling_interval: float = 2.0
    
    # Security settings
    threat_detection_enabled: bool = True
    local_rules_enabled: bool = True
    behavior_analysis_enabled: bool = True
    
    # Notification settings
    notifications_enabled: bool = True
    alert_threshold: int = 70
    
    # File monitoring paths
    monitor_paths: Optional[List[str]] = field(default_factory=lambda: [
        '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin', '/home', '/tmp', '/var/tmp', '/opt'
    ])
    
    # Exclude patterns
    exclude_paths: Optional[List[str]] = field(default_factory=lambda: [
        '/proc', '/sys', '/dev', '/run', '/var/cache'
    ])
    
    exclude_processes: Optional[List[str]] = field(default_factory=lambda: [
        'kthreadd', 'ksoftirqd', 'migration', 'rcu_'
    ])
    
    # Additional configuration
    custom_settings: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        try:
            data = {}
            for field_name, field_value in self.__dict__.items():
                if field_value is not None:
                    if isinstance(field_value, (list, dict)):
                        data[field_name] = field_value
                    else:
                        data[field_name] = field_value
            return data
        except Exception as e:
            return {'error': str(e), 'agent_id': self.agent_id}

@dataclass
class AgentUpdateData:
    """Linux Agent Update Data"""
    
    # Update information
    agent_id: str
    current_version: str
    available_version: str
    update_required: bool = False
    
    # Update details
    update_type: str = "minor"  # major, minor, patch, security
    update_size: Optional[int] = None  # bytes
    update_url: Optional[str] = None
    update_checksum: Optional[str] = None
    
    # Installation information
    install_path: Optional[str] = None
    backup_required: bool = True
    restart_required: bool = False
    
    # Compatibility information
    os_compatibility: Optional[List[str]] = field(default_factory=list)
    architecture_compatibility: Optional[List[str]] = field(default_factory=list)
    
    # Update metadata
    release_notes: Optional[str] = None
    security_fixes: Optional[List[str]] = field(default_factory=list)
    new_features: Optional[List[str]] = field(default_factory=list)
    
    # Scheduling
    scheduled_time: Optional[datetime] = None
    maintenance_window: Optional[Dict[str, str]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        try:
            data = {}
            for field_name, field_value in self.__dict__.items():
                if field_value is not None:
                    if isinstance(field_value, datetime):
                        data[field_name] = field_value.isoformat()
                    elif isinstance(field_value, (list, dict)):
                        data[field_name] = field_value
                    else:
                        data[field_name] = field_value
            return data
        except Exception as e:
            return {'error': str(e), 'agent_id': self.agent_id}

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
            ip_address=ip_address or "0.0.0.0",
            operating_system="Linux Unknown",
            os_version="Unknown",
            architecture="Unknown",
            agent_version="2.1.0-Linux"
        )

def create_linux_heartbeat_data(agent_id: str, **kwargs) -> AgentHeartbeatData:
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

def validate_agent_data(data: AgentRegistrationData) -> tuple[bool, str]:
    """Validate agent registration data"""
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
        
        # Validate hostname
        if len(data.hostname) > 255:
            return False, "Hostname too long"
        
        # Check for Linux platform
        if 'linux' not in data.operating_system.lower():
            return False, "Not a Linux system"
        
        return True, "Valid"
        
    except Exception as e:
        return False, f"Validation error: {e}"

def get_system_information() -> Dict[str, Any]:
    """Get comprehensive Linux system information"""
    try:
        info = {
            'platform': 'linux',
            'hostname': platform.node(),
            'architecture': platform.machine(),
            'kernel': platform.release(),
            'python_version': platform.python_version(),
            'processor': platform.processor(),
            'system': platform.system(),
            'version': platform.version()
        }
        
        # Get distribution information
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('NAME='):
                        info['distribution_name'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION='):
                        info['distribution_version'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('ID='):
                        info['distribution_id'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION_ID='):
                        info['distribution_version_id'] = line.split('=')[1].strip().strip('"')
        except:
            info['distribution_name'] = 'Unknown'
            info['distribution_version'] = 'Unknown'
        
        # Get CPU information
        try:
            import psutil
            info['cpu_count'] = psutil.cpu_count()
            info['cpu_count_physical'] = psutil.cpu_count(logical=False)
            info['cpu_freq'] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
        except ImportError:
            try:
                info['cpu_count'] = os.cpu_count()
            except:
                info['cpu_count'] = 1
        
        # Get memory information
        try:
            import psutil
            memory = psutil.virtual_memory()
            info['memory_total'] = memory.total
            info['memory_available'] = memory.available
        except ImportError:
            try:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            info['memory_total'] = int(line.split()[1]) * 1024
                        elif line.startswith('MemAvailable:'):
                            info['memory_available'] = int(line.split()[1]) * 1024
            except:
                pass
        
        # Get disk information
        try:
            import psutil
            disk = psutil.disk_usage('/')
            info['disk_total'] = disk.total
            info['disk_free'] = disk.free
        except ImportError:
            try:
                import shutil
                disk_total, disk_used, disk_free = shutil.disk_usage('/')
                info['disk_total'] = disk_total
                info['disk_free'] = disk_free
            except:
                pass
        
        # Get network interfaces
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            info['network_interfaces'] = list(interfaces.keys())
        except ImportError:
            try:
                import socket
                hostname = socket.gethostname()
                info['hostname_resolved'] = socket.gethostbyname(hostname)
            except:
                pass
        
        # Get uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                info['uptime_seconds'] = uptime_seconds
                info['uptime_days'] = uptime_seconds / 86400
        except:
            pass
        
        # Get load average
        try:
            info['load_average'] = os.getloadavg()
        except:
            pass
        
        # Check for containerization
        info['is_container'] = os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')
        
        # Check for virtualization
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                if 'hypervisor' in cpuinfo:
                    info['is_virtualized'] = True
                else:
                    info['is_virtualized'] = False
        except:
            info['is_virtualized'] = False
        
        return info
        
    except Exception as e:
        return {
            'platform': 'linux',
            'error': str(e),
            'hostname': platform.node(),
            'architecture': platform.machine()
        }

def get_agent_capabilities() -> List[str]:
    """Get list of Linux agent capabilities"""
    capabilities = [
        'process_monitoring',
        'file_monitoring', 
        'network_monitoring',
        'authentication_monitoring',
        'system_monitoring',
        'linux_specific_monitoring'
    ]
    
    try:
        # Check for root privileges
        if os.geteuid() == 0:
            capabilities.extend([
                'privileged_monitoring',
                'kernel_monitoring',
                'audit_monitoring',
                'container_monitoring'
            ])
        
        # Check for specific tools and features
        if os.path.exists('/proc/sys/fs/inotify'):
            capabilities.append('inotify_monitoring')
        
        if os.path.exists('/var/log/audit'):
            capabilities.append('audit_log_access')
        
        # Check for container runtimes
        import subprocess
        try:
            subprocess.run(['which', 'docker'], capture_output=True, check=True)
            capabilities.append('docker_monitoring')
        except:
            pass
        
        try:
            subprocess.run(['which', 'podman'], capture_output=True, check=True)
            capabilities.append('podman_monitoring')
        except:
            pass
        
        # Check for systemd
        try:
            subprocess.run(['which', 'systemctl'], capture_output=True, check=True)
            capabilities.append('systemd_monitoring')
        except:
            pass
        
    except Exception:
        pass
    
    return capabilities

@dataclass
class AgentRegistrationData:
    """Linux Agent Registration Data"""
    
    # Basic agent information
    hostname: str
    ip_address: str
    operating_system: str
    os_version: str
    architecture: str
    agent_version: str
    
    # Network information
    mac_address: Optional[str] = None
    domain: Optional[str] = None
    
    # Installation information
    install_path: Optional[str] = None
    
    # Linux-specific information
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
    
    # Status information
    status: str = "Active"
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: int = 0
    
    # Monitoring settings
    monitoring_enabled: bool = True
    
    # Timestamps
    registration_time: datetime = field(default_factory=datetime.now)
    
    # Additional metadata
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization to populate Linux-specific data"""
        try:
            # Ensure metadata exists
            if not self.metadata:
                self.metadata = {}
            
            # Add platform identifier
            self.metadata['platform'] = 'linux'
            
            # Get Linux distribution info if not provided
            if not self.distribution:
                try:
                    with open('/etc/os-release', 'r') as f:
                        for line in f:
                            if line.startswith('NAME='):
                                self.distribution = line.split('=')[1].strip().strip('"')
                            elif line.startswith('VERSION='):
                                self.distribution_version = line.split('=')[1].strip().strip('"')
                except:
                    pass
            
            # Get kernel version if not provided
            if not self.kernel_version:
                self.kernel_version = platform.release()
            
            # Check root privileges
            self.has_root_privileges = os.geteuid() == 0
            
            # Get current user info
            if not self.current_user:
                try:
                    import pwd
                    self.current_user = pwd.getpwuid(os.getuid()).pw_name
                    self.effective_user = pwd.getpwuid(os.geteuid()).pw_name
                except:
                    pass
            
            # Get user groups
            if not self.user_groups:
                try:
                    import grp
                    self.user_groups = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]
                except:
                    self.user_groups = []
            
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
            
            # Check for specific processes
            try:
                import subprocess
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                processes = result.stdout.lower()
                
                if 'gnome-session' in processes:
                    return 'GNOME'
                elif 'kded' in processes or 'plasma' in processes:
                    return 'KDE'
                elif 'xfce4-session' in processes:
                    return 'XFCE'
                elif 'mate-session' in processes:
                    return 'MATE'
            except:
                pass
            
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
        """Convert to dictionary for JSON serialization"""
        try:
            data = {}
            for field_name, field_value in self.__dict__.items():
                if field_value is not None:
                    if isinstance(field_value, datetime):
                        data[field_name] = field_value.isoformat()
                    elif isinstance(field_value, (list, dict)):
                        data[field_name] = field_value
                    else:
                        data[field_name] = field_value
            return data
        except Exception as e:
            return {'error': str(e), 'hostname': self.hostname}

@dataclass
class AgentHeartbeatData:
    """Linux Agent Heartbeat Data"""
    
    # Basic information
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    status: str = "Active"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Performance metrics
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: int = 0
    
    # System uptime
    uptime: Optional[float] = None
    agent_uptime: Optional[float] = None
    
    # Collector status
    collector_status: Optional[Dict[str, str]] = field(default_factory=dict)
    
    # Event statistics
    events_collected: int = 0
    events_sent: int = 0
    events_failed: int = 0
    alerts_received: int = 0
    
    # Linux-specific metrics
    load_average: Optional[List[float]] = field(default_factory=list)
    memory_details: Optional[Dict[str, int]] = field(default_factory=dict)
    disk_details: Optional[Dict[str, Any]] = field(default_factory=dict)
    network_details: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    # Process information
    active_processes: int = 0
    agent_process_id: Optional[int] = None
    
    # Security status
    security_status: str = "Normal"
    threat_level: str = "Low"
    
    # Additional metadata
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization to collect Linux system metrics"""
        try:
            # Ensure metadata exists
            if not self.metadata:
                self.metadata = {}
            
            # Add platform identifier
            self.metadata['platform'] = 'linux'
            
            # Get system uptime
            if self.uptime is None:
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
            
            # Get load average
            if not self.load_average:
                try:
                    self.load_average = list(os.getloadavg())
                except:
                    pass
            
            # Get memory details
            if not self.memory_details:
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
            
            # Get disk details
            if not self.disk_details:
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
            
            # Get network details
            if not self.network_details:
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
            
            # Get process count
            if self.active_processes == 0:
                try:
                    import psutil
                    self.active_processes = len(psutil.pids())
                except:
                    try:
                        self.active_processes = len(os.listdir('/proc'))
                    except:
                        pass
            
            # Get agent process ID
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
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        try:
            data = {}
            for field_name, field_value in self.__dict__.items():
                if field_value is not None:
                    if isinstance(field_value, (list, dict)):
                        data[field_name] = field_value
                    else:
                        data[field_name] = field_value
            return data
        except Exception as e:
            return {'error': str(e), 'agent_id': self.agent_id}

@dataclass
class AgentStatusData:
    """Linux Agent Status Data"""
    
    # Basic status
    agent_id: str
    hostname: str
    status: str = "Unknown"
    last_seen: datetime = field(default_factory=datetime.now)
    
    # Health information
    is_healthy: bool = True
    health_issues: Optional[List[str]] = field(default_factory=list)
    
    # Performance metrics
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    
    # Monitoring status
    is_monitoring: bool = False
    collectors_running: int = 0
    collectors_total: int = 0
    
    # Event processing
    events_per_minute: float = 0.0
    queue_utilization: float = 0.0
    processing_errors: int = 0
    
    # Security status
    threats_detected: int = 0
    alerts_generated: int = 0
    last_threat_time: Optional[datetime] = None
    
    # Linux-specific status
    kernel_version: Optional[str] = None
    distribution: Optional[str] = None
    has_root_privileges: bool = False
    
    # Additional information
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        try:
            data = {}
            for field_name, field_value in self.__dict__.items():
                if field_value is not None:
                    if isinstance(field_value, datetime):
                        data[field_name] = field_value.isoformat()
                    elif isinstance(field_value, (list, dict)):
                        data[field_name] = field_value
                    else:
                        data[field_name] = field_value
            return data
        except Exception as e:
            return {'error': str(e), 'agent_id': self.agent_id}

@dataclass
class AgentEventData:
    """Linux Agent Event Data"""
    
    # Event identification
    event_id: str
    agent_id: str
    event_type: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Event details
    severity: str = "Info"
    source: str = "Agent"
    category: str = "System"
    
    # Event data
    data: Optional[Dict[str, Any]] = field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = field(default_factory=dict)
    
    # Processing information
    processed: bool = False
    sent_to_server: bool = False
    retry_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        try:
            data = {}
            for field_name, field_value in self.__dict__.items():
                if field_value is not None:
                    if isinstance(field_value, datetime):
                        data[field_name] = field_value.isoformat()
                    elif isinstance(field_value, (list, dict)):
                        data[field_name] = field_value
                    else:
                        data[field_name] = field_value
            return data
        except Exception as e:
            return {'error': str(e), 'event_id': self.event_id}