# agent/core/agent_manager.py - OPTIMIZED Linux Agent Manager
"""
Linux Agent Manager - OPTIMIZED VERSION
Enhanced stability, performance monitoring, and error handling
"""

import asyncio
import logging
import time
import uuid
import platform
import psutil
import os
import pwd
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path
import socket
import getpass
import subprocess

from agent.core.communication import ServerCommunication
from agent.core.config_manager import ConfigManager
from agent.core.event_processor import EventProcessor
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from agent.collectors.process_collector import LinuxProcessCollector
from agent.collectors.file_collector import LinuxFileCollector
from agent.collectors.network_collector import LinuxNetworkCollector
from agent.collectors.authentication_collector import LinuxAuthenticationCollector
from agent.collectors.system_collector import LinuxSystemCollector

class LinuxAgentManager:
    """✅ OPTIMIZED: Linux Agent Manager with enhanced stability"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # ✅ OPTIMIZATION: Enhanced state management
        self.requires_root = True
        self.has_root_privileges = self._check_root_privileges()
        self.is_initialized = False
        self.is_running = False
        self.is_monitoring = False
        self.is_paused = False
        self.is_registered = False
        self.start_time = None
        self.last_heartbeat = None
        
        # ✅ OPTIMIZATION: Improved agent ID management
        self.agent_id_file = os.path.join(os.path.dirname(__file__), '..', '..', '.agent_id')
        self.agent_id = self._load_or_create_agent_id()
        
        if not self.agent_id:
            self.agent_id = str(uuid.uuid4())
            self._save_agent_id(self.agent_id)
        
        self.system_info = self._get_linux_system_info()
        
        # Core components
        self.communication = None
        self.event_processor = None
        self.collectors = {}
        
        # ✅ OPTIMIZATION: Performance monitoring
        self.performance_stats = {
            'events_processed': 0,
            'collector_errors': 0,
            'memory_usage_mb': 0,
            'cpu_usage_percent': 0,
            'last_performance_check': time.time()
        }
        
        # ✅ OPTIMIZATION: Health monitoring
        self.health_checks = {
            'communication': True,
            'event_processor': True,
            'collectors': {},
            'last_health_check': time.time()
        }
        
        # ✅ OPTIMIZATION: System stats
        self.system_stats = {
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'memory_available_mb': 0,
            'disk_usage': 0.0,
            'disk_free_gb': 0,
            'last_system_check': time.time(),
            'boot_time': psutil.boot_time(),
            'uptime_seconds': time.time() - psutil.boot_time()
        }
        
        self.logger.info(f"🐧 Linux Agent Manager initialized with ID: {self.agent_id[:8]}...")
        self.logger.info(f"🔐 Root privileges: {self.has_root_privileges}")
        self.logger.info(f"⚙️ Requires root: {self.requires_root}")
    
    def _check_root_privileges(self) -> bool:
        """Check if running with root privileges"""
        try:
            return os.geteuid() == 0
        except Exception as e:
            self.logger.error(f"❌ Error checking root privileges: {e}")
            return False
    
    def _load_or_create_agent_id(self) -> str:
        """Load or create agent ID with better error handling"""
        try:
            if os.path.exists(self.agent_id_file):
                with open(self.agent_id_file, 'r') as f:
                    agent_id = f.read().strip()
                    if agent_id and len(agent_id) >= 32:
                        return agent_id
            
            new_agent_id = str(uuid.uuid4())
            self._save_agent_id(new_agent_id)
            return new_agent_id
            
        except Exception as e:
            self.logger.error(f"❌ Error with agent ID: {e}")
            return str(uuid.uuid4())
    
    def _save_agent_id(self, agent_id: str):
        """Save agent ID to file"""
        try:
            os.makedirs(os.path.dirname(self.agent_id_file), exist_ok=True)
            with open(self.agent_id_file, 'w') as f:
                f.write(agent_id)
            os.chmod(self.agent_id_file, 0o600)
        except Exception as e:
            self.logger.error(f"Could not save agent ID: {e}")
    
    def _get_linux_system_info(self) -> Dict[str, str]:
        """Get comprehensive Linux system information"""
        try:
            system_info = {}
            
            # Basic system info
            system_info['hostname'] = socket.gethostname()
            system_info['architecture'] = platform.machine()
            system_info['kernel'] = platform.release()
            system_info['current_user'] = getpass.getuser()
            system_info['is_root'] = os.geteuid() == 0
            
            # Distribution info
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = f.read()
                    for line in os_release.split('\n'):
                        if line.startswith('PRETTY_NAME='):
                            system_info['distribution'] = line.split('=', 1)[1].strip('"')
                            break
            except:
                system_info['distribution'] = 'Unknown'
            
            # CPU info
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpu_info = f.read()
                    for line in cpu_info.split('\n'):
                        if line.startswith('model name'):
                            system_info['cpu_model'] = line.split(':', 1)[1].strip()
                            break
            except:
                system_info['cpu_model'] = 'Unknown'
            
            # Memory info
            try:
                with open('/proc/meminfo', 'r') as f:
                    mem_info = f.read()
                    for line in mem_info.split('\n'):
                        if line.startswith('MemTotal:'):
                            mem_total = int(line.split()[1]) // 1024  # Convert to MB
                            system_info['memory_total_mb'] = str(mem_total)
                            break
            except:
                system_info['memory_total_mb'] = 'Unknown'
            
            # Network interfaces
            try:
                system_info['network_interfaces'] = []
                for interface in os.listdir('/sys/class/net'):
                    if interface != 'lo':  # Skip loopback
                        system_info['network_interfaces'].append(interface)
            except:
                system_info['network_interfaces'] = []
            
            self.logger.info(f"✅ System info collected: {system_info['hostname']} ({system_info['distribution']})")
            return system_info
                
        except Exception as e:
            self.logger.error(f"❌ Error getting system info: {e}")
            return {
                'hostname': 'unknown',
                'architecture': 'unknown',
                'kernel': 'unknown',
                'distribution': 'unknown',
                'current_user': 'unknown',
                'is_root': False
            }
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Try to get IP from socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Doesn't actually connect, just gets local IP
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
            except Exception:
                ip = '127.0.0.1'
            finally:
                s.close()
            
            self.logger.debug(f"📡 Local IP detected: {ip}")
            return ip
            
        except Exception as e:
            self.logger.error(f"❌ Error getting local IP: {e}")
            return '127.0.0.1'
    
    def _get_mac_address(self) -> str:
        """Get MAC address of primary network interface"""
        try:
            # Get primary network interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('8.8.8.8', 80))
                interface = s.getsockname()[0]
            except Exception:
                interface = 'lo'
            finally:
                s.close()
            
            # Get MAC address
            try:
                with open(f'/sys/class/net/{interface}/address', 'r') as f:
                    mac = f.read().strip()
                    self.logger.debug(f"📡 MAC address: {mac}")
                    return mac
            except:
                # Fallback: try to get from ifconfig
                try:
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'ether' in line:
                                mac = line.split('ether')[1].strip().split()[0]
                                return mac
                except:
                    pass
                
                return '00:00:00:00:00:00'
                
        except Exception as e:
            self.logger.error(f"❌ Error getting MAC address: {e}")
            return '00:00:00:00:00:00'
    
    def _get_domain(self) -> str:
        """Get domain name"""
        try:
            domain = socket.getfqdn()
            if domain and domain != socket.gethostname():
                return domain
            else:
                return 'local'
        except Exception as e:
            self.logger.error(f"❌ Error getting domain: {e}")
            return 'local'
    
    async def initialize(self):
        """Initialize Linux Agent Manager with enhanced error handling"""
        try:
            self.logger.info("🚀 Starting Linux Agent Manager initialization...")
            
            await self._check_system_requirements()
            
            # Initialize Communication with retries
            await self._initialize_communication_with_retries()
            
            # Initialize Event Processor
            await self._initialize_event_processor()
            
            # Initialize Collectors with selective enabling
            await self._initialize_collectors_optimized()
            
            self.is_initialized = True
            self.logger.info("🎉 Linux Agent Manager initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent manager initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")
            raise Exception(f"Linux agent manager initialization failed: {e}")
    
    async def _initialize_communication_with_retries(self):
        """Initialize communication with retry logic"""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                self.logger.info("📡 Initializing Server Communication...")
                self.communication = ServerCommunication(self.config_manager)
                await self.communication.initialize()
                self.logger.info("✅ Server Communication initialized")
                
                # Test connectivity
                self.logger.info("🔍 Testing server connectivity...")
                if await self.communication.test_server_connection():
                    self.logger.info("✅ Server connection test passed")
                    break
                else:
                    raise Exception("Server connection test failed")
                    
            except Exception as e:
                self.logger.warning(f"❌ Communication attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    self.logger.info(f"⏳ Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    raise Exception(f"Communication initialization failed after {max_retries} attempts")
    
    async def _initialize_event_processor(self):
        """Initialize Event Processor with validation"""
        try:
            self.logger.info("⚙️ Initializing Event Processor...")
            self.event_processor = EventProcessor(
                self.config_manager, 
                self.communication
            )

            if self.agent_id:
                self.event_processor.set_agent_id(self.agent_id)
                self.logger.info(f"✅ Event Processor initialized with agent_id: {self.agent_id[:8]}...")
            else:
                raise Exception("No agent_id available for event processor")
    
        except Exception as e:
            self.logger.error(f"❌ Event processor initialization failed: {e}")
            raise Exception(f"Event processor failed: {e}")
            
    async def _initialize_collectors_optimized(self):
        """Initialize collectors with optimization and selective enabling"""
        try:
            self.logger.info("📊 Initializing Collectors (Optimized)...")
            
            agent_config = self.config.get('agent', {})
            
            # ✅ OPTIMIZATION: Selective collector initialization based on config
            collectors_config = {
                'process': {
                    'enabled': agent_config.get('enable_process_collector', True),
                    'class': LinuxProcessCollector,
                    'priority': 1  # High priority
                },
                'network': {
                    'enabled': agent_config.get('enable_network_collector', True),
                    'class': LinuxNetworkCollector,
                    'priority': 2  # Medium priority
                },
                'authentication': {
                    'enabled': agent_config.get('enable_authentication_collector', True),
                    'class': LinuxAuthenticationCollector,
                    'priority': 3  # High priority for security
                },
                'system': {
                    'enabled': agent_config.get('enable_system_collector', True),
                    'class': LinuxSystemCollector,
                    'priority': 4  # Medium priority
                },
                'file': {
                    'enabled': agent_config.get('enable_file_collector', False),  # Disabled by default
                    'class': LinuxFileCollector,
                    'priority': 5  # Low priority - can cause spam
                }
            }
            
            # Sort collectors by priority
            sorted_collectors = sorted(collectors_config.items(), key=lambda x: x[1]['priority'])
            
            # Initialize collectors in priority order
            for collector_name, config in sorted_collectors:
                if config['enabled']:
                    try:
                        self.logger.info(f"📊 Initializing {collector_name} collector...")
                        
                        collector = config['class'](self.config_manager)
                        collector.set_agent_id(self.agent_id)
                        collector.set_event_processor(self.event_processor)
                        
                        # ✅ OPTIMIZATION: Add collector health check
                        try:
                            await collector.initialize()
                            self.collectors[collector_name] = collector
                            self.health_checks['collectors'][collector_name] = True
                            self.logger.info(f"✅ {collector_name} collector initialized")
                        except Exception as e:
                            self.logger.error(f"❌ Failed to initialize {collector_name}: {e}")
                            self.health_checks['collectors'][collector_name] = False
                            # Continue with other collectors instead of failing completely
                            
                    except Exception as e:
                        self.logger.error(f"❌ Error creating {collector_name} collector: {e}")
                        self.health_checks['collectors'][collector_name] = False
                else:
                    self.logger.info(f"⏭️ {collector_name} collector disabled in config")
            
            self.logger.info(f"✅ Initialized {len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Collector initialization failed: {e}")
            # Don't raise exception - allow agent to continue with available collectors
    
    async def _check_system_requirements(self):
        """Check Linux system requirements with enhanced validation"""
        try:
            self.logger.info("🔍 Checking Linux system requirements...")
            
            # Check agent ID
            if not self.agent_id:
                raise Exception("Agent ID not available")
            else:
                self.logger.info(f"✅ Agent ID available: {self.agent_id[:8]}...")
            
            # Check root privileges
            if self.requires_root and not self.has_root_privileges:
                self.logger.warning("⚠️ Linux agent running without root privileges - monitoring may be limited")
            else:
                self.logger.info("✅ Root privileges available for enhanced monitoring")
            
            # Check system resources
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            
            self.logger.info(f"🖥️ System Resources:")
            self.logger.info(f"   🔄 CPU Cores: {cpu_count}")
            self.logger.info(f"   💾 Memory: {memory.total / (1024**3):.1f} GB")
            self.logger.info(f"   💽 Available Memory: {memory.available / (1024**3):.1f} GB")
            
            # ✅ OPTIMIZATION: Check for minimum requirements
            if memory.available < 512 * 1024 * 1024:  # 512MB
                self.logger.warning("⚠️ Low available memory - performance may be affected")
            
            if cpu_count < 2:
                self.logger.warning("⚠️ Limited CPU cores - reducing collector workers")
                # Adjust worker counts for low-resource systems
                if hasattr(self, 'config'):
                    agent_config = self.config.get('agent', {})
                    agent_config['num_workers'] = 1
                    agent_config['num_batch_processors'] = 1
            
            # Check critical filesystem access
            critical_paths = ['/proc', '/sys', '/etc']
            for path in critical_paths:
                if not os.path.exists(path):
                    self.logger.warning(f"⚠️ Critical path not available: {path}")
                elif not os.access(path, os.R_OK):
                    self.logger.warning(f"⚠️ Cannot read critical path: {path}")
                else:
                    self.logger.debug(f"✅ Access to {path}")
            
        except Exception as e:
            self.logger.error(f"❌ System requirements check failed: {e}")
            raise
    
    async def start(self):
        """Start Linux Agent Manager with enhanced monitoring"""
        try:
            self.logger.info("🚀 Starting Linux Agent Manager...")
            
            # Register with server if not already registered
            if not self.is_registered:
                await self._register_with_server()
            
            # Ensure agent_id is available
            if not self.agent_id:
                raise Exception("Agent registration failed - no agent_id received")
            
            self.logger.info(f"✅ Agent ready with ID: {self.agent_id}")
            
            # Update agent_id everywhere after successful registration
            await self._update_all_agent_ids()
            
            # Start Event Processor
            self.logger.info("⚡ Starting Event Processor...")
            await self.event_processor.start()
            self.logger.info("✅ Event Processor started")
            
            # Start collectors with error handling
            await self._start_collectors_safely()
            
            # Set final running state
            self.is_running = True
            self.is_monitoring = True
            self.start_time = datetime.now()
            
            # Start monitoring tasks
            asyncio.create_task(self._heartbeat_loop())
            asyncio.create_task(self._system_monitor())
            asyncio.create_task(self._performance_monitor())  # ✅ NEW: Performance monitoring
            asyncio.create_task(self._health_monitor())       # ✅ NEW: Health monitoring
            
            self.logger.info(f"🎉 Linux Agent Manager started successfully")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   📊 Active Collectors: {len(self.collectors)}")
            self.logger.info(f"   🐧 Platform: Linux ({self.system_info.get('distribution', 'Unknown')})")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent manager start failed: {e}")
            raise
    
    async def _start_collectors_safely(self):
        """Start collectors with individual error handling"""
        try:
            self.logger.info("🚀 Starting collectors...")
            
            successful_starts = 0
            for collector_name, collector in self.collectors.items():
                try:
                    await collector.start()
                    self.logger.info(f"✅ {collector_name} collector started")
                    successful_starts += 1
                except Exception as e:
                    self.logger.error(f"❌ Error starting {collector_name} collector: {e}")
                    self.health_checks['collectors'][collector_name] = False
                    # Remove failed collector from active collectors
                    # Don't raise exception - continue with other collectors
            
            self.logger.info(f"✅ Successfully started {successful_starts}/{len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Error in collector startup: {e}")
            # Don't raise exception - allow agent to continue with available collectors
    
    async def _register_with_server(self):
        """Register with server with enhanced data collection"""
        try:
            if self.is_registered and self.agent_id:
                self.logger.info(f"✅ Agent already registered with ID: {self.agent_id[:8]}...")
                return True
            
            self.logger.info("📡 Registering Linux Agent with complete data...")
            
            # Get comprehensive system information
            ip_address = self._get_local_ip()
            mac_address = self._get_mac_address()
            
            # Get current system metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Create registration data with ALL required fields
            registration_data = AgentRegistrationData(
                hostname=self.system_info['hostname'],
                ip_address=ip_address,
                operating_system=f"Linux {self.system_info.get('distribution', 'Unknown')}",
                os_version=self.system_info.get('kernel', 'Unknown'),
                architecture=self.system_info.get('architecture', 'Unknown'),
                agent_version='2.1.0-Linux-Optimized',
                mac_address=mac_address,
                domain=self._get_domain(),
                install_path=str(Path(__file__).resolve().parent.parent.parent),
                status="Active",
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                network_latency=0,
                monitoring_enabled=True,
                platform="linux",
                kernel_version=self.system_info.get('kernel'),
                distribution=self.system_info.get('distribution'),
                current_user=self.system_info.get('current_user'),
                has_root_privileges=self.system_info.get('is_root', False)
            )
            
            # Log registration details
            self.logger.info(f"📋 Registration Details:")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   🖥️ Hostname: {registration_data.hostname}")
            self.logger.info(f"   🌐 IP Address: {registration_data.ip_address}")
            self.logger.info(f"   🐧 OS: {registration_data.operating_system}")
            self.logger.info(f"   🌐 Domain: {registration_data.domain}")
            
            # Register agent with server
            self.logger.info("📝 Registering agent with server...")
            registration_result = await self.communication.register_agent(registration_data)
            
            if registration_result and (registration_result.get('success') or registration_result.get('agent_id')):
                returned_agent_id = registration_result.get('agent_id')
                if returned_agent_id:
                    self.agent_id = returned_agent_id
                    self.is_registered = True
                    self.logger.info(f"✅ Agent registered successfully: {self.agent_id}")
                    return True
                else:
                    self.logger.error("❌ Registration successful but no agent_id returned")
                    return False
            else:
                error_msg = registration_result.get('error', 'Unknown error') if registration_result else 'No response'
                self.logger.error(f"❌ Agent registration failed: {error_msg}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Agent registration failed: {e}")
            raise
    
    async def _update_all_agent_ids(self):
        """Update agent_id in all components after successful registration"""
        try:
            self.logger.info(f"🔄 Updating agent_id in all components: {self.agent_id[:8]}...")
            
            # Update event processor
            if self.event_processor:
                if hasattr(self.event_processor, 'agent_id'):
                    self.event_processor.agent_id = self.agent_id
                    self.logger.debug("✅ Event processor agent_id updated")
            
            # Update all collectors
            for name, collector in self.collectors.items():
                if hasattr(collector, 'agent_id'):
                    collector.agent_id = self.agent_id
                    self.logger.debug(f"✅ {name} collector agent_id updated")
            
            # Update communication
            if self.communication:
                if hasattr(self.communication, 'agent_id'):
                    self.communication.agent_id = self.agent_id
                    self.logger.debug("✅ Communication agent_id updated")
            
            self.logger.info("✅ All components updated with new agent_id")
            
        except Exception as e:
            self.logger.error(f"❌ Error updating agent_ids: {e}")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to server"""
        try:
            while self.is_running and not self.is_paused:
                try:
                    await self.send_heartbeat()
                    
                    # Get heartbeat interval from config
                    heartbeat_interval = self.config.get('agent', {}).get('heartbeat_interval', 60)
                    await asyncio.sleep(heartbeat_interval)
                    
                except Exception as e:
                    self.logger.error(f"❌ Heartbeat error: {e}")
                    await asyncio.sleep(30)  # Wait 30 seconds before retry
                    
        except Exception as e:
            self.logger.error(f"❌ Heartbeat loop failed: {e}")
    
    async def _system_monitor(self):
        """Monitor system resources and health"""
        try:
            while self.is_running and not self.is_paused:
                try:
                    # Get system metrics
                    cpu_percent = psutil.cpu_percent(interval=1)
                    memory = psutil.virtual_memory()
                    disk = psutil.disk_usage('/')
                    
                    # Update system stats
                    self.system_stats.update({
                        'cpu_usage': cpu_percent,
                        'memory_usage': memory.percent,
                        'memory_available_mb': memory.available // (1024 * 1024),
                        'disk_usage': disk.percent,
                        'disk_free_gb': disk.free // (1024 * 1024 * 1024),
                        'last_system_check': time.time()
                    })
                    
                    # Check thresholds and log warnings
                    cpu_threshold = self.config.get('agent', {}).get('cpu_threshold', 90)
                    memory_threshold = self.config.get('agent', {}).get('memory_threshold', 80)
                    
                    if cpu_percent > cpu_threshold:
                        self.logger.warning(f"⚠️ High CPU usage: {cpu_percent:.1f}% (threshold: {cpu_threshold}%)")
                    
                    if memory.percent > memory_threshold:
                        self.logger.warning(f"⚠️ High memory usage: {memory.percent:.1f}% (threshold: {memory_threshold}%)")
                    
                    # Get system monitor interval from config
                    monitor_interval = self.config.get('agent', {}).get('system_monitor_interval', 60)
                    await asyncio.sleep(monitor_interval)
                    
                except Exception as e:
                    self.logger.error(f"❌ System monitoring error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ System monitor failed: {e}")
    
    async def _performance_monitor(self):
        """✅ NEW: Monitor agent performance"""
        try:
            while self.is_running and not self.is_paused:
                try:
                    # Get current process metrics
                    current_process = psutil.Process()
                    cpu_percent = current_process.cpu_percent()
                    memory_info = current_process.memory_info()
                    memory_mb = memory_info.rss / 1024 / 1024
                    
                    # Update performance stats
                    self.performance_stats.update({
                        'memory_usage_mb': memory_mb,
                        'cpu_usage_percent': cpu_percent,
                        'last_performance_check': time.time()
                    })
                    
                    # Log warnings for high resource usage
                    if cpu_percent > 25:  # More than 25% CPU
                        self.logger.warning(f"⚠️ High CPU usage: {cpu_percent:.1f}%")
                    
                    if memory_mb > 256:  # More than 256MB
                        self.logger.warning(f"⚠️ High memory usage: {memory_mb:.1f}MB")
                    
                    # Get event processor stats
                    if self.event_processor:
                        try:
                            ep_stats = self.event_processor.get_stats()
                            self.performance_stats['events_processed'] = ep_stats.get('events_sent', 0)
                        except:
                            pass
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Performance monitoring error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ Performance monitor failed: {e}")
    
    async def _health_monitor(self):
        """✅ NEW: Monitor component health"""
        try:
            while self.is_running and not self.is_paused:
                try:
                    # Check communication health
                    if self.communication:
                        self.health_checks['communication'] = self.communication.is_online()
                    
                    # Check event processor health
                    if self.event_processor:
                        self.health_checks['event_processor'] = self.event_processor.is_running
                    
                    # Check collector health
                    for name, collector in self.collectors.items():
                        if hasattr(collector, 'is_running'):
                            self.health_checks['collectors'][name] = collector.is_running
                        else:
                            self.health_checks['collectors'][name] = True  # Assume healthy if no status
                    
                    # Log health summary every 5 minutes
                    if int(time.time()) % 300 == 0:
                        healthy_collectors = sum(1 for status in self.health_checks['collectors'].values() if status)
                        total_collectors = len(self.health_checks['collectors'])
                        
                        self.logger.info("🏥 Health Status:")
                        self.logger.info(f"   📡 Communication: {'✅' if self.health_checks['communication'] else '❌'}")
                        self.logger.info(f"   ⚡ Event Processor: {'✅' if self.health_checks['event_processor'] else '❌'}")
                        self.logger.info(f"   📊 Collectors: {healthy_collectors}/{total_collectors} healthy")
                    
                    self.health_checks['last_health_check'] = time.time()
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"❌ Health monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self.logger.error(f"❌ Health monitor failed: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get enhanced agent status with performance and health metrics"""
        status = {
            'agent_type': 'linux',
            'agent_id': self.agent_id,
            'is_initialized': self.is_initialized,
            'is_running': self.is_running,
            'is_monitoring': self.is_monitoring,
            'is_paused': self.is_paused,
            'is_registered': self.is_registered,
            'system_info': self.system_info,
            'collectors': list(self.collectors.keys()),
            'collector_status': self._get_collector_status(),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'has_root_privileges': self.has_root_privileges,
            'requires_root': self.requires_root,
            # ✅ NEW: Enhanced metrics
            'performance_stats': self.performance_stats,
            'health_checks': self.health_checks,
            'version': '2.1.0-Optimized'
        }
        return status
    
    async def stop(self):
        """Stop the agent manager and all components"""
        try:
            self.logger.info("🛑 Stopping Linux Agent Manager...")
            self.is_running = False
            self.is_monitoring = False
            
            # Stop all collectors
            if self.collectors:
                self.logger.info("🛑 Stopping collectors...")
                for name, collector in self.collectors.items():
                    try:
                        if hasattr(collector, 'stop'):
                            await collector.stop()
                            self.logger.info(f"✅ {name} collector stopped")
                    except Exception as e:
                        self.logger.error(f"❌ Error stopping {name} collector: {e}")
            
            # Stop event processor
            if self.event_processor:
                try:
                    await self.event_processor.stop()
                    self.logger.info("✅ Event processor stopped")
                except Exception as e:
                    self.logger.error(f"❌ Error stopping event processor: {e}")
            
            # Close communication
            if self.communication:
                try:
                    await self.communication.close()
                    self.logger.info("✅ Communication closed")
                except Exception as e:
                    self.logger.error(f"❌ Error closing communication: {e}")
            
            self.logger.info("✅ Linux Agent Manager stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping agent manager: {e}")
    
    def _get_collector_status(self) -> Dict[str, Any]:
        """Get status of all collectors"""
        status = {}
        for name, collector in self.collectors.items():
            try:
                if hasattr(collector, 'is_running'):
                    status[name] = {
                        'running': collector.is_running,
                        'type': type(collector).__name__
                    }
                else:
                    status[name] = {
                        'running': True,  # Assume running if no status method
                        'type': type(collector).__name__
                    }
            except Exception as e:
                status[name] = {
                    'running': False,
                    'error': str(e),
                    'type': type(collector).__name__
                }
        return status
    
    async def send_heartbeat(self):
        """Send heartbeat to server"""
        try:
            if not self.is_registered or not self.agent_id:
                self.logger.debug("Skipping heartbeat - agent not registered")
                return
            
            # Get current system metrics
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Create heartbeat data - FIXED: Remove event_count parameter
            heartbeat_data = AgentHeartbeatData(
                agent_id=self.agent_id,
                hostname=self.system_info['hostname'],  # Add hostname field
                timestamp=datetime.now().isoformat(),  # Use string timestamp instead of datetime object
                status="Active",
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                uptime=time.time() - psutil.boot_time(),
                events_sent=self.performance_stats.get('events_processed', 0),  # Use events_sent instead
                collector_status=self._get_collector_status()
            )
            
            # Send heartbeat
            if self.communication:
                await self.communication.send_heartbeat(heartbeat_data)
                self.last_heartbeat = datetime.now()
                self.logger.debug(f"💓 Heartbeat sent - CPU: {cpu_usage:.1f}%, Memory: {memory.percent:.1f}%")
            
        except Exception as e:
            self.logger.error(f"❌ Error sending heartbeat: {e}")
    
    async def pause(self):
        """Pause the agent manager"""
        try:
            self.logger.info("⏸️ Pausing Linux Agent Manager...")
            self.is_paused = True
            
            # Pause collectors
            for name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'pause'):
                        await collector.pause()
                        self.logger.info(f"⏸️ {name} collector paused")
                except Exception as e:
                    self.logger.error(f"❌ Error pausing {name} collector: {e}")
            
            self.logger.info("✅ Linux Agent Manager paused")
            
        except Exception as e:
            self.logger.error(f"❌ Error pausing agent manager: {e}")
    
    async def resume(self):
        """Resume the agent manager"""
        try:
            self.logger.info("▶️ Resuming Linux Agent Manager...")
            self.is_paused = False
            
            # Resume collectors
            for name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'resume'):
                        await collector.resume()
                        self.logger.info(f"▶️ {name} collector resumed")
                except Exception as e:
                    self.logger.error(f"❌ Error resuming {name} collector: {e}")
            
            self.logger.info("✅ Linux Agent Manager resumed")
            
        except Exception as e:
            self.logger.error(f"❌ Error resuming agent manager: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        return self.performance_stats.copy()
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        return self.health_checks.copy() 