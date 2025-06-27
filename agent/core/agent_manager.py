# agent/core/agent_manager.py - FIXED Linux Agent Manager
"""
Linux Agent Manager - FIXED VERSION
Main orchestrator for Linux EDR agent with proper imports
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

from agent.core.communication import ServerCommunication  # FIXED IMPORT
from agent.core.config_manager import ConfigManager
from agent.core.event_processor import EventProcessor  # FIXED IMPORT
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData

class LinuxAgentManager:
    """
    Linux Agent Manager - FIXED VERSION
    Main orchestrator for the Linux EDR agent
    """
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Agent state
        self.is_initialized = False
        self.is_running = False
        self.is_monitoring = False
        self.is_paused = False
        
        # Agent identification
        self.agent_id_file = os.path.join(os.path.dirname(__file__), '..', '..', '.agent_id')
        self.agent_id = self._load_or_create_agent_id()
        self.is_registered = False
        
        # Linux system information
        self.system_info = self._get_linux_system_info()
        
        # Core components
        self.communication = None
        self.event_processor = None
        self.collectors = {}
        
        # Performance tracking
        self.start_time = None
        self.last_heartbeat = None
        
        # Linux-specific settings
        self.requires_root = True
        self.has_root_privileges = os.geteuid() == 0
        
        self.logger.info(f"🐧 Linux Agent Manager initialized")
        self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
        self.logger.info(f"   🖥️ System: {self.system_info.get('distribution', 'Unknown')} {self.system_info.get('version', '')}")
        self.logger.info(f"   🔒 Root privileges: {self.has_root_privileges}")
    
    def _load_or_create_agent_id(self) -> str:
        """Load existing agent ID or create new one"""
        try:
            # Try to load existing agent ID
            if os.path.exists(self.agent_id_file):
                with open(self.agent_id_file, 'r') as f:
                    agent_id = f.read().strip()
                    if agent_id and len(agent_id) >= 32:
                        self.logger.info(f"📋 Loaded existing agent ID: {agent_id[:8]}...")
                        return agent_id
            
            # Create new agent ID
            new_agent_id = str(uuid.uuid4())
            
            # Save to file
            try:
                os.makedirs(os.path.dirname(self.agent_id_file), exist_ok=True)
                with open(self.agent_id_file, 'w') as f:
                    f.write(new_agent_id)
                os.chmod(self.agent_id_file, 0o600)
                self.logger.info(f"🆕 Created new agent ID: {new_agent_id[:8]}...")
            except Exception as e:
                self.logger.error(f"❌ Could not save agent ID: {e}")
            
            return new_agent_id
            
        except Exception as e:
            self.logger.error(f"❌ Error with agent ID: {e}")
            # Fallback to generated ID
            fallback_id = str(uuid.uuid4())
            self.logger.warning(f"⚠️ Using fallback agent ID: {fallback_id[:8]}...")
            return fallback_id
    
    def _get_linux_system_info(self) -> Dict[str, str]:
        """Get Linux system information"""
        try:
            info = {
                'hostname': platform.node(),
                'kernel': platform.release(),
                'architecture': platform.machine(),
                'distribution': 'Unknown',
                'version': 'Unknown',
                'platform': 'linux'
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
            
            # Get additional system info
            try:
                info['uptime'] = time.time() - psutil.boot_time()
                info['cpu_count'] = psutil.cpu_count()
                
                memory = psutil.virtual_memory()
                info['total_memory'] = memory.total
                
                # Get current user
                info['current_user'] = pwd.getpwuid(os.getuid()).pw_name
                info['effective_user'] = pwd.getpwuid(os.geteuid()).pw_name
                
            except Exception as e:
                self.logger.debug(f"Error getting additional system info: {e}")
            
            return info
            
        except Exception as e:
            self.logger.error(f"❌ Error getting Linux system info: {e}")
            return {'error': str(e), 'platform': 'linux'}
    
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
                await self._initialize_collectors()
                self.logger.info("✅ Collectors initialized")
            except Exception as e:
                self.logger.error(f"❌ Collector initialization failed: {e}")
                raise Exception(f"Collectors failed: {e}")
            
            self.is_initialized = True
            self.logger.info("🎉 Linux Agent Manager initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent manager initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")
            raise Exception(f"Linux agent manager initialization failed: {e}")
    
    async def _check_system_requirements(self):
        """Check Linux system requirements"""
        try:
            self.logger.info("🔍 Checking Linux system requirements...")
            
            # Check agent ID
            if not self.agent_id:
                raise Exception("Agent ID not available")
            else:
                self.logger.info(f"✅ Agent ID available: {self.agent_id[:8]}...")
            
            # Check root privileges for enhanced monitoring
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
        """Initialize data collectors"""
        try:
            from agent.collectors.process_collector import LinuxProcessCollector
            from agent.collectors.file_collector import LinuxFileCollector
            from agent.collectors.network_collector import LinuxNetworkCollector
            from agent.collectors.authentication_collector import LinuxAuthenticationCollector
            from agent.collectors.system_collector import LinuxSystemCollector
            
            # Configure which collectors to enable
            collection_config = self.config.get('collection', {})
            
            collectors_to_init = {}
            
            if collection_config.get('collect_processes', True):
                collectors_to_init['process'] = LinuxProcessCollector
            
            if collection_config.get('collect_files', True):
                collectors_to_init['file'] = LinuxFileCollector
            
            if collection_config.get('collect_network', True):
                collectors_to_init['network'] = LinuxNetworkCollector
            
            if collection_config.get('collect_authentication', True):
                collectors_to_init['authentication'] = LinuxAuthenticationCollector
            
            if collection_config.get('collect_system_events', True):
                collectors_to_init['system'] = LinuxSystemCollector
            
            # Initialize collectors
            for collector_name, collector_class in collectors_to_init.items():
                try:
                    self.logger.info(f"📊 Initializing {collector_name} collector...")
                    collector = collector_class(self.config_manager)
                    
                    # Set event processor and agent_id
                    collector.set_event_processor(self.event_processor)
                    if self.agent_id:
                        collector.set_agent_id(self.agent_id)
                    
                    # Initialize collector
                    await collector.initialize()
                    
                    self.collectors[collector_name] = collector
                    self.logger.info(f"✅ {collector_name} collector initialized")
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to initialize {collector_name} collector: {e}")
                    # Continue with other collectors
            
            self.logger.info(f"✅ Initialized {len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Collector initialization failed: {e}")
            raise
    
    async def start(self):
        """Start Linux Agent Manager"""
        try:
            self.logger.info("🚀 Starting Linux Agent Manager...")
            
            # Register with server FIRST
            await self._register_with_server()
            
            # Ensure agent_id is available
            if not self.agent_id:
                raise Exception("Agent registration failed - no agent_id received")
            
            self.logger.info(f"✅ Agent registered with ID: {self.agent_id}")
            
            # Update agent_id everywhere after successful registration
            await self._update_all_agent_ids()
            
            # Start Event Processor
            self.logger.info("⚡ Starting Event Processor...")
            await self.event_processor.start()
            self.logger.info("✅ Event Processor started")
            
            # Start Collectors
            self.logger.info("📊 Starting Collectors...")
            for collector_name, collector in self.collectors.items():
                try:
                    await collector.start()
                    self.logger.info(f"✅ {collector_name} collector started")
                except Exception as e:
                    self.logger.error(f"❌ Failed to start {collector_name} collector: {e}")
            
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
            for collector_name, collector in self.collectors.items():
                try:
                    self.logger.info(f"📊 Stopping {collector_name} collector...")
                    await collector.stop()
                    self.logger.info(f"✅ {collector_name} collector stopped")
                except Exception as e:
                    self.logger.error(f"❌ Error stopping {collector_name} collector: {e}")
            
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
        """Register Linux Agent with EDR server"""
        try:
            self.logger.info("📡 Registering Linux Agent with EDR server...")
            
            # Get domain and log it
            domain = self._get_domain()
            self.logger.info(f"🌐 Domain for registration: {domain}")
            
            # Create registration data
            registration_data = AgentRegistrationData(
                hostname=self.system_info['hostname'],
                ip_address=self._get_local_ip(),
                operating_system=f"Linux {self.system_info.get('distribution', 'Unknown')} {self.system_info.get('version', '')}",
                os_version=self.system_info.get('kernel', 'Unknown'),
                architecture=self.system_info.get('architecture', 'Unknown'),
                agent_version='2.1.0-Linux',
                mac_address=self._get_mac_address(),
                domain=domain,
                install_path=str(Path(__file__).resolve().parent.parent.parent),
                kernel_version=self.system_info.get('kernel'),
                distribution=self.system_info.get('distribution'),
                distribution_version=self.system_info.get('version'),
                has_root_privileges=self.has_root_privileges,
                current_user=self.system_info.get('current_user'),
                effective_user=self.system_info.get('effective_user'),
                capabilities=['linux_monitoring', 'process_monitoring', 'file_monitoring']
            )
            
            # Log registration data
            self.logger.info(f"📋 Registration data:")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   🖥️ Hostname: {registration_data.hostname}")
            self.logger.info(f"   🌐 Domain: {registration_data.domain}")
            self.logger.info(f"   🐧 OS: {registration_data.operating_system}")
            
            # Send registration request
            response = await self.communication.register_agent(registration_data)
            
            if response and response.get('success'):
                # Use the agent_id from response OR keep our existing one
                server_agent_id = response.get('agent_id')
                
                if server_agent_id and server_agent_id != self.agent_id:
                    # Server assigned a new ID - update ours
                    self.logger.info(f"📋 Server assigned new agent_id: {server_agent_id[:8]}...")
                    self.agent_id = server_agent_id
                    self._save_agent_id(self.agent_id)
                else:
                    # Keep our existing agent_id
                    self.logger.info(f"📋 Using existing agent_id: {self.agent_id[:8]}...")
                
                self.is_registered = True
                
                self.logger.info(f"✅ Linux Agent registered successfully: {self.agent_id}")
                self.logger.info(f"   🖥️ Hostname: {self.system_info['hostname']}")
                self.logger.info(f"   🐧 OS: Linux {self.system_info.get('distribution', 'Unknown')}")
                
                # Update configuration with server settings
                if 'heartbeat_interval' in response:
                    self.config['agent']['heartbeat_interval'] = response['heartbeat_interval']
                    
            else:
                error_msg = response.get('error', 'Unknown error') if response else 'No response'
                raise Exception(f"Agent registration failed: {error_msg}")
                
        except Exception as e:
            self.logger.error(f"❌ Agent registration failed: {e}")
            raise
    
    def _save_agent_id(self, agent_id: str):
        """Save agent ID to file"""
        try:
            os.makedirs(os.path.dirname(self.agent_id_file), exist_ok=True)
            with open(self.agent_id_file, 'w') as f:
                f.write(agent_id)
            os.chmod(self.agent_id_file, 0o600)
            self.logger.debug(f"Agent ID saved to {self.agent_id_file}")
        except Exception as e:
            self.logger.error(f"Could not save agent ID: {e}")
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def _get_mac_address(self) -> Optional[str]:
        """Get MAC address"""
        try:
            import uuid
            mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
            return ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
        except:
            return None
    
    def _get_domain(self) -> Optional[str]:
        """Get domain name (Linux-specific)"""
        try:
            # Try to get domain from hostname
            import socket
            fqdn = socket.getfqdn()
            if '.' in fqdn:
                domain = fqdn.split('.', 1)[1]
                if domain and domain != 'localdomain':
                    return domain
            
            # Try to read from /etc/domain
            if os.path.exists('/etc/domain'):
                with open('/etc/domain', 'r') as f:
                    domain = f.read().strip()
                    if domain and domain != 'localdomain':
                        return domain
            
            # Try to get from resolv.conf
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('domain '):
                            domain = line.split()[1].strip()
                            if domain and domain != 'localdomain':
                                return domain
            
            # Fallback
            return "local.linux"
            
        except Exception as e:
            self.logger.debug(f"Could not get domain: {e}")
            return "local.linux"
    
    async def _update_all_agent_ids(self):
        """Update agent_id in all components"""
        try:
            self.logger.info(f"🔄 Updating agent_id in all components: {self.agent_id[:8]}...")
            
            # Update event processor
            if self.event_processor and self.agent_id:
                self.event_processor.set_agent_id(self.agent_id)
                self.logger.info(f"[EVENT_PROCESSOR] Updated AgentID: {self.agent_id[:8]}...")
            
            # Update collectors
            for collector_name, collector in self.collectors.items():
                if self.agent_id:
                    collector.set_agent_id(self.agent_id)
                    self.logger.info(f"[{collector_name.upper()}_COLLECTOR] Updated AgentID: {self.agent_id[:8]}...")
            
            self.logger.info("✅ All components updated with agent_id")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to update agent_id in components: {e}")
    
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
        """Send heartbeat to server"""
        try:
            if not self.is_registered or not self.communication:
                return
            
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Create heartbeat data
            heartbeat_data = AgentHeartbeatData(
                agent_id=self.agent_id,
                hostname=self.system_info['hostname'],
                status=status,
                timestamp=datetime.now().isoformat(),
                cpu_usage=cpu_percent,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                uptime=time.time() - psutil.boot_time(),
                collector_status=self._get_collector_status(),
                events_collected=self.event_processor.get_stats().get('events_received', 0) if self.event_processor else 0,
                events_sent=self.event_processor.get_stats().get('events_sent', 0) if self.event_processor else 0,
                metadata={
                    'linux_agent': True,
                    'collector_count': len(self.collectors),
                    'platform': 'linux',
                    'distribution': self.system_info.get('distribution', 'Unknown')
                }
            )
            
            await self.communication.send_heartbeat(heartbeat_data)
            self.last_heartbeat = datetime.now()
            
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
            'has_root_privileges': self.has_root_privileges
        }