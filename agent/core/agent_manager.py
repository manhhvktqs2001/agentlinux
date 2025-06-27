# agent/core/agent_manager.py - FIXED Linux Agent Manager
"""
Linux Agent Manager - FIXED VERSION
Main orchestrator for Linux EDR agent with ALL MISSING ATTRIBUTES
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
    """✅ FIXED: Linux Agent Manager with ALL required attributes"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # ✅ FIXED: Add ALL missing attributes
        self.requires_root = True  # CRITICAL FIX
        self.has_root_privileges = self._check_root_privileges()
        self.is_initialized = False
        self.is_running = False
        self.is_monitoring = False
        self.is_paused = False
        self.is_registered = False
        self.start_time = None
        self.last_heartbeat = None
        
        # ✅ FIXED: Agent identification with guaranteed agent_id
        self.agent_id_file = os.path.join(os.path.dirname(__file__), '..', '..', '.agent_id')
        self.agent_id = self._load_or_create_agent_id()
        
        # ✅ FIXED: Ensure agent_id is NEVER None
        if not self.agent_id:
            self.agent_id = str(uuid.uuid4())
            self._save_agent_id(self.agent_id)
        
        self.system_info = self._get_linux_system_info()
        
        # Core components
        self.communication = None
        self.event_processor = None
        self.collectors = {}
        
        self.logger.info(f"🐧 Linux Agent Manager initialized with ID: {self.agent_id[:8]}...")
        self.logger.info(f"🔐 Root privileges: {self.has_root_privileges}")
        self.logger.info(f"⚙️ Requires root: {self.requires_root}")
    
    def _check_root_privileges(self) -> bool:
        """✅ FIXED: Check if running with root privileges"""
        try:
            return os.geteuid() == 0
        except Exception as e:
            self.logger.error(f"❌ Error checking root privileges: {e}")
            return False
    
    def _load_or_create_agent_id(self) -> str:
        """✅ FIXED: Guaranteed agent_id creation"""
        try:
            # Try to load existing
            if os.path.exists(self.agent_id_file):
                with open(self.agent_id_file, 'r') as f:
                    agent_id = f.read().strip()
                    if agent_id and len(agent_id) >= 32:
                        return agent_id
            
            # Create new agent_id
            new_agent_id = str(uuid.uuid4())
            self._save_agent_id(new_agent_id)
            return new_agent_id
            
        except Exception as e:
            self.logger.error(f"❌ Error with agent ID: {e}")
            # ✅ FIXED: Always return a valid agent_id
            return str(uuid.uuid4())
    
    def _save_agent_id(self, agent_id: str):
        """✅ FIXED: Save agent_id to file"""
        try:
            os.makedirs(os.path.dirname(self.agent_id_file), exist_ok=True)
            with open(self.agent_id_file, 'w') as f:
                f.write(agent_id)
            os.chmod(self.agent_id_file, 0o600)
        except Exception as e:
            self.logger.error(f"Could not save agent ID: {e}")
    
    def _get_linux_system_info(self) -> Dict[str, str]:
        """Get Linux system information from actual system"""
        try:
            info = {
                'hostname': platform.node(),
                'kernel': platform.release(),
                'architecture': platform.machine(),
                'distribution': 'Unknown',
                'version': 'Unknown',
                'platform': 'linux',
                'is_root': self.has_root_privileges
            }
            
            # Get distribution info from /etc/os-release
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('NAME='):
                            info['distribution'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('VERSION='):
                            info['version'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('VERSION_ID='):
                            info['version_id'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('ID='):
                            info['distribution_id'] = line.split('=')[1].strip().strip('"')
            except Exception as e:
                self.logger.debug(f"Could not read /etc/os-release: {e}")
            
            # Get additional system info from actual system
            try:
                info['uptime'] = time.time() - psutil.boot_time()
                info['cpu_count'] = psutil.cpu_count()
                info['cpu_count_logical'] = psutil.cpu_count(logical=True)
                
                memory = psutil.virtual_memory()
                info['total_memory'] = memory.total
                info['available_memory'] = memory.available
                info['memory_percent'] = memory.percent
                
                # Get current user from actual system
                info['current_user'] = pwd.getpwuid(os.getuid()).pw_name
                info['effective_user'] = pwd.getpwuid(os.geteuid()).pw_name
                
                # Get system load average
                try:
                    load_avg = os.getloadavg()
                    info['load_average_1min'] = load_avg[0]
                    info['load_average_5min'] = load_avg[1]
                    info['load_average_15min'] = load_avg[2]
                except:
                    pass
                
                # Get disk usage
                try:
                    disk = psutil.disk_usage('/')
                    info['disk_total'] = disk.total
                    info['disk_used'] = disk.used
                    info['disk_free'] = disk.free
                    info['disk_percent'] = disk.percent
                except:
                    pass
                
                # Get network interfaces
                try:
                    net_if_addrs = psutil.net_if_addrs()
                    info['network_interfaces'] = list(net_if_addrs.keys())
                except:
                    pass
                
                # Get system timezone
                try:
                    import time
                    info['timezone'] = time.tzname[time.daylight]
                except:
                    pass
                
            except Exception as e:
                self.logger.debug(f"Error getting additional system info: {e}")
            
            return info
            
        except Exception as e:
            self.logger.error(f"❌ Error getting Linux system info: {e}")
            return {'error': str(e), 'platform': 'linux', 'is_root': self.has_root_privileges}
    
    async def initialize(self):
        """Initialize Linux Agent Manager and all components"""
        try:
            self.logger.info("🚀 Starting Linux Agent Manager initialization...")
            
            # Check system requirements
            await self._check_system_requirements()
            
            # Initialize Communication
            try:
                self.logger.info("📡 Initializing Server Communication...")
                self.communication = ServerCommunication(self.config_manager)
                await self.communication.initialize()
                self.logger.info("✅ Server Communication initialized")
                
                # Test server connection
                self.logger.info("🔍 Testing server connectivity...")
                if await self.communication.test_server_connection():
                    self.logger.info("✅ Server connection test passed")
                    
                    # Test batch endpoint
                    if await self.communication.test_batch_endpoint():
                        self.logger.info("✅ Batch endpoint test passed")
                    else:
                        self.logger.warning("⚠️ Batch endpoint test failed - will use individual submissions")
                else:
                    self.logger.error("❌ Server connection test failed")
                    
            except Exception as e:
                self.logger.error(f"❌ Communication initialization failed: {e}")
                raise Exception(f"Communication failed: {e}")
            
            # Initialize Event Processor
            try:
                self.logger.info("⚙️ Initializing Event Processor...")
                self.event_processor = EventProcessor(
                    self.config_manager, 
                    self.communication
                )
                # Set agent_id immediately
                if self.agent_id:
                    self.event_processor.set_agent_id(self.agent_id)
                    self.logger.info(f"✅ Event Processor initialized with agent_id: {self.agent_id[:8]}...")
                else:
                    raise Exception("No agent_id available for event processor")
            except Exception as e:
                self.logger.error(f"❌ Event processor initialization failed: {e}")
                raise Exception(f"Event processor failed: {e}")
            
            # Initialize Collectors
            try:
                self.logger.info("📊 Initializing Collectors...")
                
                # Debug config values
                agent_config = self.config.get('agent', {})
                self.logger.info(f"🔍 Config debug - agent section: {agent_config}")
                
                enable_process = agent_config.get('enable_process_collector', True)
                enable_file = agent_config.get('enable_file_collector', True)
                enable_network = agent_config.get('enable_network_collector', True)
                enable_auth = agent_config.get('enable_authentication_collector', True)
                enable_system = agent_config.get('enable_system_collector', True)
                
                self.logger.info(f"🔍 Collector enable flags:")
                self.logger.info(f"   Process: {enable_process}")
                self.logger.info(f"   File: {enable_file}")
                self.logger.info(f"   Network: {enable_network}")
                self.logger.info(f"   Auth: {enable_auth}")
                self.logger.info(f"   System: {enable_system}")
                
                # Process collector
                if enable_process:
                    self.logger.info("📊 Initializing process collector...")
                    self.process_collector = LinuxProcessCollector(self.config_manager)
                    self.process_collector.set_agent_id(self.agent_id)
                    self.process_collector.set_event_processor(self.event_processor)
                    await self.process_collector.initialize()
                    self.logger.info("✅ process collector initialized")
                else:
                    self.logger.info("⏭️ Process collector disabled in config")
                    self.process_collector = None
                
                # File collector
                if enable_file:
                    self.logger.info("📊 Initializing file collector...")
                    self.file_collector = LinuxFileCollector(self.config_manager)
                    self.file_collector.set_agent_id(self.agent_id)
                    self.file_collector.set_event_processor(self.event_processor)
                    await self.file_collector.initialize()
                    self.logger.info("✅ file collector initialized")
                else:
                    self.logger.info("⏭️ File collector disabled in config")
                    self.file_collector = None
                
                # Network collector
                if enable_network:
                    self.logger.info("📊 Initializing network collector...")
                    self.network_collector = LinuxNetworkCollector(self.config_manager)
                    self.network_collector.set_agent_id(self.agent_id)
                    self.network_collector.set_event_processor(self.event_processor)
                    await self.network_collector.initialize()
                    self.logger.info("✅ network collector initialized")
                else:
                    self.logger.info("⏭️ Network collector disabled in config")
                    self.network_collector = None
                
                # Authentication collector
                if enable_auth:
                    self.logger.info("📊 Initializing authentication collector...")
                    self.authentication_collector = LinuxAuthenticationCollector(self.config_manager)
                    self.authentication_collector.set_agent_id(self.agent_id)
                    self.authentication_collector.set_event_processor(self.event_processor)
                    await self.authentication_collector.initialize()
                    self.logger.info("✅ authentication collector initialized")
                else:
                    self.logger.info("⏭️ Authentication collector disabled in config")
                    self.authentication_collector = None
                
                # System collector
                if enable_system:
                    self.logger.info("📊 Initializing system collector...")
                    self.system_collector = LinuxSystemCollector(self.config_manager)
                    self.system_collector.set_agent_id(self.agent_id)
                    self.system_collector.set_event_processor(self.event_processor)
                    await self.system_collector.initialize()
                    self.logger.info("✅ system collector initialized")
                else:
                    self.logger.info("⏭️ System collector disabled in config")
                    self.system_collector = None
                
                # Add enabled collectors to dict
                if self.process_collector:
                    self.collectors['process'] = self.process_collector
                if self.file_collector:
                    self.collectors['file'] = self.file_collector
                if self.network_collector:
                    self.collectors['network'] = self.network_collector
                if self.authentication_collector:
                    self.collectors['authentication'] = self.authentication_collector
                if self.system_collector:
                    self.collectors['system'] = self.system_collector
                
                self.logger.info(f"✅ Initialized {len(self.collectors)} collectors")
                
            except Exception as e:
                self.logger.error(f"❌ Collector initialization failed: {e}")
                raise
            
            self.is_initialized = True
            self.logger.info("🎉 Linux Agent Manager initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent manager initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")
            raise Exception(f"Linux agent manager initialization failed: {e}")
    
    async def _check_system_requirements(self):
        """✅ FIXED: Check Linux system requirements with proper attribute checking"""
        try:
            self.logger.info("🔍 Checking Linux system requirements...")
            
            # Check agent ID
            if not self.agent_id:
                raise Exception("Agent ID not available")
            else:
                self.logger.info(f"✅ Agent ID available: {self.agent_id[:8]}...")
            
            # ✅ FIXED: Check root privileges with proper attribute access
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
    
    async def _initialize_collectors(self):
        """Initialize data collectors with debug logging"""
        try:
            # Initialize collectors based on config
            self.logger.info("📊 Initializing Collectors...")
            
            # Debug config values
            agent_config = self.config.get('agent', {})
            self.logger.info(f"🔍 Config debug - agent section: {agent_config}")
            
            enable_process = agent_config.get('enable_process_collector', True)
            enable_file = agent_config.get('enable_file_collector', True)
            enable_network = agent_config.get('enable_network_collector', True)
            enable_auth = agent_config.get('enable_authentication_collector', True)
            enable_system = agent_config.get('enable_system_collector', True)
            
            self.logger.info(f"🔍 Collector enable flags:")
            self.logger.info(f"   Process: {enable_process}")
            self.logger.info(f"   File: {enable_file}")
            self.logger.info(f"   Network: {enable_network}")
            self.logger.info(f"   Auth: {enable_auth}")
            self.logger.info(f"   System: {enable_system}")
            
            # Process collector
            if enable_process:
                self.logger.info("📊 Initializing process collector...")
                self.process_collector = LinuxProcessCollector(self.config_manager)
                self.process_collector.set_agent_id(self.agent_id)
                self.process_collector.set_event_processor(self.event_processor)
                await self.process_collector.initialize()
                self.logger.info("✅ process collector initialized")
            else:
                self.logger.info("⏭️ Process collector disabled in config")
                self.process_collector = None
            
            # File collector
            if enable_file:
                self.logger.info("📊 Initializing file collector...")
                self.file_collector = LinuxFileCollector(self.config_manager)
                self.file_collector.set_agent_id(self.agent_id)
                self.file_collector.set_event_processor(self.event_processor)
                await self.file_collector.initialize()
                self.logger.info("✅ file collector initialized")
            else:
                self.logger.info("⏭️ File collector disabled in config")
                self.file_collector = None
            
            # Network collector
            if enable_network:
                self.logger.info("📊 Initializing network collector...")
                self.network_collector = LinuxNetworkCollector(self.config_manager)
                self.network_collector.set_agent_id(self.agent_id)
                self.network_collector.set_event_processor(self.event_processor)
                await self.network_collector.initialize()
                self.logger.info("✅ network collector initialized")
            else:
                self.logger.info("⏭️ Network collector disabled in config")
                self.network_collector = None
            
            # Authentication collector
            if enable_auth:
                self.logger.info("📊 Initializing authentication collector...")
                self.authentication_collector = LinuxAuthenticationCollector(self.config_manager)
                self.authentication_collector.set_agent_id(self.agent_id)
                self.authentication_collector.set_event_processor(self.event_processor)
                await self.authentication_collector.initialize()
                self.logger.info("✅ authentication collector initialized")
            else:
                self.logger.info("⏭️ Authentication collector disabled in config")
                self.authentication_collector = None
            
            # System collector
            if enable_system:
                self.logger.info("📊 Initializing system collector...")
                self.system_collector = LinuxSystemCollector(self.config_manager)
                self.system_collector.set_agent_id(self.agent_id)
                self.system_collector.set_event_processor(self.event_processor)
                await self.system_collector.initialize()
                self.logger.info("✅ system collector initialized")
            else:
                self.logger.info("⏭️ System collector disabled in config")
                self.system_collector = None
            
            # Add enabled collectors to dict
            if self.process_collector:
                self.collectors['process'] = self.process_collector
            if self.file_collector:
                self.collectors['file'] = self.file_collector
            if self.network_collector:
                self.collectors['network'] = self.network_collector
            if self.authentication_collector:
                self.collectors['authentication'] = self.authentication_collector
            if self.system_collector:
                self.collectors['system'] = self.system_collector
            
            self.logger.info(f"✅ Initialized {len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Collector initialization failed: {e}")
            raise
    
    async def start(self):
        """Start Linux Agent Manager"""
        try:
            self.logger.info("🚀 Starting Linux Agent Manager...")
            
            # ✅ FIXED: Check if already registered before attempting registration
            if self.is_registered and self.agent_id:
                self.logger.info(f"✅ Agent already registered with ID: {self.agent_id[:8]}...")
                self.logger.info(f"   🖥️ Hostname: {self.system_info['hostname']}")
                self.logger.info(f"   🌐 IP: {self._get_local_ip()}")
                self.logger.info(f"   🐧 OS: Linux {self.system_info.get('distribution', 'Unknown')}")
            else:
                # Register with server FIRST
                self.logger.info("📡 Agent not registered - attempting registration...")
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
            
            # Start collectors
            self.logger.info("🚀 Starting collectors...")
            
            try:
                if hasattr(self, 'process_collector') and self.process_collector:
                    await self.process_collector.start()
                    self.logger.info("✅ process collector started")
                
                if hasattr(self, 'file_collector') and self.file_collector:
                    await self.file_collector.start()
                    self.logger.info("✅ file collector started")
                
                if hasattr(self, 'network_collector') and self.network_collector:
                    await self.network_collector.start()
                    self.logger.info("✅ network collector started")
                
                if hasattr(self, 'authentication_collector') and self.authentication_collector:
                    await self.authentication_collector.start()
                    self.logger.info("✅ authentication collector started")
                
                if hasattr(self, 'system_collector') and self.system_collector:
                    await self.system_collector.start()
                    self.logger.info("✅ system collector started")
            except Exception as e:
                self.logger.error(f"❌ Error starting collectors: {e}")
            
            # Set final running state
            self.is_running = True
            self.is_monitoring = True
            self.start_time = datetime.now()
            
            # Start monitoring tasks
            asyncio.create_task(self._heartbeat_loop())
            asyncio.create_task(self._system_monitor())
            
            self.logger.info(f"🎉 Linux Agent Manager started successfully")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   📊 Active Collectors: {len(self.collectors)}")
            self.logger.info(f"   🐧 Platform: Linux ({self.system_info.get('distribution', 'Unknown')})")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent manager start failed: {e}")
            raise
    
    async def stop(self):
        """Stop Linux Agent Manager gracefully"""
        try:
            self.logger.info("🛑 Stopping Linux Agent Manager...")
            
            # Set running state
            self.is_running = False
            self.is_monitoring = False
            
            # Stop collectors
            self.logger.info("🛑 Stopping collectors...")
            
            try:
                if hasattr(self, 'process_collector') and self.process_collector:
                    self.logger.info("📊 Stopping process collector...")
                    await self.process_collector.stop()
                    self.logger.info("✅ process collector stopped")
                
                if hasattr(self, 'file_collector') and self.file_collector:
                    self.logger.info("📊 Stopping file collector...")
                    await self.file_collector.stop()
                    self.logger.info("✅ file collector stopped")
                
                if hasattr(self, 'network_collector') and self.network_collector:
                    self.logger.info("📊 Stopping network collector...")
                    await self.network_collector.stop()
                    self.logger.info("✅ network collector stopped")
                
                if hasattr(self, 'authentication_collector') and self.authentication_collector:
                    self.logger.info("📊 Stopping authentication collector...")
                    await self.authentication_collector.stop()
                    self.logger.info("✅ authentication collector stopped")
                
                if hasattr(self, 'system_collector') and self.system_collector:
                    self.logger.info("📊 Stopping system collector...")
                    await self.system_collector.stop()
                    self.logger.info("✅ system collector stopped")
            except Exception as e:
                self.logger.error(f"❌ Error stopping collectors: {e}")
            
            # Stop event processor
            if self.event_processor:
                self.logger.info("⚡ Stopping Event Processor...")
                await self.event_processor.stop()
                self.logger.info("✅ Event Processor stopped")
            
            # Close communication
            if self.communication:
                self.logger.info("📡 Closing Communication...")
                await self.communication.close()
                self.logger.info("✅ Communication closed")
            
            # Send final heartbeat
            if self.is_registered:
                try:
                    await self._send_heartbeat(status='Offline')
                except:
                    pass
            
            self.logger.info("🎉 Linux Agent Manager stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping Linux agent manager: {e}")
    
    async def _register_with_server(self):
        """✅ FIXED: Registration with ALL required fields and duplicate check"""
        try:
            # ✅ FIXED: Check if already registered
            if self.is_registered and self.agent_id:
                self.logger.info(f"✅ Agent already registered with ID: {self.agent_id[:8]}...")
                self.logger.info(f"   🖥️ Hostname: {self.system_info['hostname']}")
                self.logger.info(f"   🌐 IP: {self._get_local_ip()}")
                self.logger.info(f"   🐧 OS: Linux {self.system_info.get('distribution', 'Unknown')}")
                return True
            
            self.logger.info("📡 Registering Linux Agent with complete data...")
            
            # ✅ FIXED: Get complete system information
            import psutil
            
            # Get network interface info
            ip_address = self._get_local_ip()
            mac_address = self._get_mac_address()
            
            # Get current system metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # ✅ FIXED: Create registration data with ALL required fields
            registration_data = AgentRegistrationData(
                hostname=self.system_info['hostname'],
                ip_address=ip_address,
                operating_system=f"Linux {self.system_info.get('distribution', 'Unknown')}",
                os_version=self.system_info.get('kernel', 'Unknown'),
                architecture=self.system_info.get('architecture', 'Unknown'),
                agent_version='2.1.0-Linux',
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
            
            # ✅ FIXED: Log registration details
            self.logger.info(f"📋 Registration Details:")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   🖥️ Hostname: {registration_data.hostname}")
            self.logger.info(f"   🌐 IP Address: {registration_data.ip_address}")
            self.logger.info(f"   🐧 OS: {registration_data.operating_system}")
            self.logger.info(f"   🌐 Domain: {registration_data.domain}")
            
            # ✅ FIXED: Register agent with server
            self.logger.info("📝 Registering agent with server...")
            registration_result = await self.communication.register_agent(registration_data)
            
            if registration_result and (registration_result.get('success') or registration_result.get('agent_id')):
                self.agent_id = registration_result.get('agent_id')
                if self.agent_id:
                    self.logger.info(f"✅ Agent registered successfully: {self.agent_id}")
                    
                    # ✅ FIXED: Test event submission after registration (optional)
                    test_event_submission = self.config.get('agent', {}).get('test_event_submission', False)
                    if test_event_submission:
                        self.logger.info("🧪 Testing event submission...")
                        test_success = await self.communication.test_event_submission()
                        if test_success:
                            self.logger.info("✅ Event submission test passed")
                        else:
                            self.logger.warning("⚠️ Event submission test failed - will continue anyway")
                    else:
                        self.logger.info("⏭️ Skipping event submission test (disabled in config)")
                    
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
    
    def _get_local_ip(self) -> str:
        """Get actual local IP address from system"""
        try:
            # Try multiple methods to get the actual local IP
            import socket
            
            # Method 1: Connect to external service
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and ip != "127.0.0.1":
                    return ip
            except:
                pass
            
            # Method 2: Get from network interfaces
            try:
                import psutil
                net_if_addrs = psutil.net_if_addrs()
                for interface, addrs in net_if_addrs.items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                            return addr.address
            except:
                pass
            
            # Method 3: Get hostname and resolve
            try:
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                if ip and ip != "127.0.0.1":
                    return ip
            except:
                pass
            
            # Method 4: Get from environment (if set)
            import os
            if 'HOSTNAME' in os.environ:
                try:
                    ip = socket.gethostbyname(os.environ['HOSTNAME'])
                    if ip and ip != "127.0.0.1":
                        return ip
                except:
                    pass
            
            # Fallback to localhost
            return "127.0.0.1"
            
        except Exception as e:
            self.logger.debug(f"Error getting local IP: {e}")
            return "127.0.0.1"
    
    def _get_mac_address(self) -> str:
        """Get actual MAC address from network interfaces"""
        try:
            import psutil
            import socket
            
            # Get MAC address from the primary network interface
            net_if_addrs = psutil.net_if_addrs()
            
            # Look for the first non-loopback interface with a MAC address
            for interface, addrs in net_if_addrs.items():
                # Skip loopback and virtual interfaces
                if interface.startswith('lo') or interface.startswith('docker') or interface.startswith('veth'):
                    continue
                    
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:  # MAC address
                        return addr.address
                    elif hasattr(addr, 'family') and addr.family == socket.AF_PACKET:  # Linux specific
                        return addr.address
            
            # If no MAC found, try to get from /sys/class/net
            try:
                import os
                for interface in os.listdir('/sys/class/net'):
                    if interface.startswith('lo') or interface.startswith('docker'):
                        continue
                    mac_path = f'/sys/class/net/{interface}/address'
                    if os.path.exists(mac_path):
                        with open(mac_path, 'r') as f:
                            mac = f.read().strip()
                            if mac and mac != "00:00:00:00:00:00":
                                return mac
            except:
                pass
            
            # Fallback to UUID-based method
            try:
                import uuid
                mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                               for ele in range(0,8*6,8)][::-1])
                return mac
            except:
                return "00:00:00:00:00:00"
                
        except Exception as e:
            self.logger.debug(f"Error getting MAC address: {e}")
            return "00:00:00:00:00:00"
    
    def _get_domain(self) -> str:
        """Get actual system domain from configuration"""
        try:
            import socket
            
            # Method 1: Get from /etc/hostname and /etc/hosts
            try:
                with open('/etc/hostname', 'r') as f:
                    hostname = f.read().strip()
                    if '.' in hostname:
                        return hostname.split('.', 1)[1]
            except:
                pass
            
            # Method 2: Get from /etc/resolv.conf
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('domain '):
                            domain = line.split()[1].strip()
                            if domain and domain != 'localdomain':
                                return domain
                        elif line.startswith('search '):
                            domain = line.split()[1].strip()
                            if domain and domain != 'localdomain':
                                return domain
            except:
                pass
            
            # Method 3: Get from socket.getfqdn()
            try:
                fqdn = socket.getfqdn()
                if '.' in fqdn and not fqdn.endswith('.localdomain'):
                    return fqdn.split('.', 1)[1]
            except:
                pass
            
            # Method 4: Get from environment variables
            import os
            for env_var in ['DOMAIN', 'HOSTNAME', 'HOST']:
                if env_var in os.environ:
                    value = os.environ[env_var]
                    if '.' in value and not value.endswith('.localdomain'):
                        return value.split('.', 1)[1]
            
            # Method 5: Try to get from DNS
            try:
                hostname = socket.gethostname()
                fqdn = socket.gethostbyaddr(socket.gethostbyname(hostname))[0]
                if '.' in fqdn and not fqdn.endswith('.localdomain'):
                    return fqdn.split('.', 1)[1]
            except:
                pass
            
            # Fallback to local.linux
            return "local.linux"
            
        except Exception as e:
            self.logger.debug(f"Error getting domain: {e}")
            return "local.linux"
    
    async def _update_all_agent_ids(self):
        """✅ FIXED: Update agent_id in ALL components"""
        try:
            if not self.agent_id:
                raise Exception("Cannot update components - agent_id is None")
            
            self.logger.info(f"🔄 Updating agent_id in all components: {self.agent_id[:8]}...")
            
            # ✅ FIXED: Update event processor
            if self.event_processor:
                self.event_processor.set_agent_id(self.agent_id)
                self.logger.info(f"[EVENT_PROCESSOR] Updated AgentID: {self.agent_id[:8]}...")
            
            # ✅ FIXED: Update all collectors
            for collector_name, collector in self.collectors.items():
                if hasattr(collector, 'set_agent_id'):
                    collector.set_agent_id(self.agent_id)
                    self.logger.info(f"[{collector_name.upper()}_COLLECTOR] Updated AgentID: {self.agent_id[:8]}...")
            
            self.logger.info("✅ All components updated with agent_id")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to update agent_id in components: {e}")
            raise
    
    async def _heartbeat_loop(self):
        """Heartbeat loop"""
        try:
            while self.is_running:
                try:
                    if self.is_registered and self.communication:
                        await self._send_heartbeat()
                    
                    # Get heartbeat interval from config
                    interval = self.config.get('agent', {}).get('heartbeat_interval', 30)
                    await asyncio.sleep(interval)
                    
                except Exception as e:
                    self.logger.error(f"❌ Heartbeat error: {e}")
                    await asyncio.sleep(10)  # Wait before retry
                    
        except asyncio.CancelledError:
            self.logger.info("🛑 Heartbeat loop cancelled")
        except Exception as e:
            self.logger.error(f"❌ Heartbeat loop failed: {e}")
    
    async def _send_heartbeat(self, status: str = 'Active'):
        """Send heartbeat to server with real system data"""
        try:
            if not self.is_registered or not self.communication:
                return
            
            # Get comprehensive system metrics from actual system
            try:
                # CPU metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                cpu_count = psutil.cpu_count()
                cpu_freq = psutil.cpu_freq()
                cpu_stats = psutil.cpu_stats()
                
                # Memory metrics
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                # Disk metrics
                disk = psutil.disk_usage('/')
                disk_io = psutil.disk_io_counters()
                
                # Network metrics
                net_io = psutil.net_io_counters()
                net_if_stats = psutil.net_if_stats()
                
                # System load
                load_avg = os.getloadavg()
                
                # Process metrics
                process_count = len(psutil.pids())
                
                # System uptime
                uptime = time.time() - psutil.boot_time()
                
                # Get collector statistics
                collector_stats = {}
                for name, collector in self.collectors.items():
                    if hasattr(collector, 'get_stats'):
                        collector_stats[name] = collector.get_stats()
                
                # Create comprehensive heartbeat data
                heartbeat_data = AgentHeartbeatData(
                    agent_id=self.agent_id,
                    hostname=self.system_info['hostname'],
                    status=status,
                    timestamp=datetime.now().isoformat(),
                    cpu_usage=cpu_percent,
                    memory_usage=memory.percent,
                    disk_usage=disk.percent,
                    network_latency=0,  # Will be calculated if needed
                    uptime=uptime,
                    collector_status=self._get_collector_status(),
                    events_collected=self.event_processor.get_stats().get('events_received', 0) if self.event_processor else 0,
                    events_sent=self.event_processor.get_stats().get('events_sent', 0) if self.event_processor else 0,
                    events_failed=self.event_processor.get_stats().get('events_failed', 0) if self.event_processor else 0,
                    alerts_received=0,  # Will be updated when alerts are implemented
                    load_average=list(load_avg),
                    memory_details={
                        'total': memory.total,
                        'available': memory.available,
                        'used': memory.used,
                        'free': memory.free,
                        'swap_total': swap.total,
                        'swap_used': swap.used,
                        'swap_free': swap.free
                    },
                    disk_details={
                        'total': disk.total,
                        'used': disk.used,
                        'free': disk.free,
                        'read_bytes': disk_io.read_bytes if disk_io else 0,
                        'write_bytes': disk_io.write_bytes if disk_io else 0
                    },
                    network_details={
                        'bytes_sent': net_io.bytes_sent,
                        'bytes_recv': net_io.bytes_recv,
                        'packets_sent': net_io.packets_sent,
                        'packets_recv': net_io.packets_recv,
                        'interface_count': len(net_if_stats)
                    },
                    active_processes=process_count,
                    agent_process_id=os.getpid(),
                    security_status="Normal",  # Will be updated based on security events
                    threat_level="Low",  # Will be updated based on threat detection
                    metadata={
                        'linux_agent': True,
                        'collector_count': len(self.collectors),
                        'platform': 'linux',
                        'distribution': self.system_info.get('distribution', 'Unknown'),
                        'kernel': self.system_info.get('kernel', 'Unknown'),
                        'architecture': self.system_info.get('architecture', 'Unknown'),
                        'cpu_count': cpu_count,
                        'cpu_freq_mhz': cpu_freq.current if cpu_freq else 0,
                        'cpu_ctx_switches': cpu_stats.ctx_switches if cpu_stats else 0,
                        'cpu_interrupts': cpu_stats.interrupts if cpu_stats else 0,
                        'collector_stats': collector_stats,
                        'system_load_1min': load_avg[0],
                        'system_load_5min': load_avg[1],
                        'system_load_15min': load_avg[2]
                    }
                )
                
                await self.communication.send_heartbeat(heartbeat_data)
                self.last_heartbeat = datetime.now()
                
            except Exception as e:
                self.logger.error(f"❌ Error collecting system metrics: {e}")
                # Send basic heartbeat if detailed collection fails
                basic_heartbeat = AgentHeartbeatData(
                    agent_id=self.agent_id,
                    hostname=self.system_info['hostname'],
                    status=status,
                    timestamp=datetime.now().isoformat(),
                    cpu_usage=psutil.cpu_percent(interval=1),
                    memory_usage=psutil.virtual_memory().percent,
                    disk_usage=psutil.disk_usage('/').percent,
                    metadata={'linux_agent': True, 'error': str(e)}
                )
                await self.communication.send_heartbeat(basic_heartbeat)
            
        except Exception as e:
            self.logger.error(f"❌ Heartbeat send failed: {e}")
    
    def _get_collector_status(self) -> Dict[str, str]:
        """Get collector status"""
        status = {}
        try:
            for collector_name, collector in self.collectors.items():
                if hasattr(collector, 'is_running'):
                    status[collector_name] = 'running' if collector.is_running else 'stopped'
                else:
                    status[collector_name] = 'unknown'
        except Exception as e:
            self.logger.debug(f"Error getting collector status: {e}")
        
        return status
    
    async def _system_monitor(self):
        """System monitoring"""
        try:
            self.logger.info("🔍 Starting Linux system monitor...")
            
            while self.is_running and not self.is_paused:
                try:
                    # Monitor system resources
                    await self._check_system_resources()
                    
                    # Wait before next check
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ System monitor error: {e}")
                    await asyncio.sleep(30)
                    
        except asyncio.CancelledError:
            self.logger.info("🛑 System monitor cancelled")
        except Exception as e:
            self.logger.error(f"❌ System monitor failed: {e}")
    
    async def _check_system_resources(self):
        """Check system resources"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                self.logger.warning(f"⚠️ High CPU usage: {cpu_percent}%")
            
            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                self.logger.warning(f"⚠️ High memory usage: {memory.percent}%")
            
            # Disk usage
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                self.logger.warning(f"⚠️ High disk usage: {disk.percent}%")
                
        except Exception as e:
            self.logger.debug(f"System resource check error: {e}")
    
    async def pause(self):
        """Pause agent monitoring"""
        try:
            if not self.is_paused:
                self.is_paused = True
                self.logger.info("⏸️ Linux Agent monitoring PAUSED")
                
                # Send pause status
                if self.is_registered:
                    try:
                        await self._send_heartbeat(status='Paused')
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"❌ Agent pause error: {e}")
    
    async def resume(self):
        """Resume agent monitoring"""
        try:
            if self.is_paused:
                self.is_paused = False
                self.logger.info("▶️ Linux Agent monitoring RESUMED")
                
                # Send active status
                if self.is_registered:
                    try:
                        await self._send_heartbeat(status='Active')
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"❌ Agent resume error: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
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
            'requires_root': self.requires_root  # ✅ FIXED: Added this attribute
        }