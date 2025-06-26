# agent/core/agent_manager.py - Linux Agent Manager
"""
Linux Agent Manager - Core agent management and coordination for Linux systems
Optimized for Linux EDR monitoring with platform-specific features
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
from agent.collectors.process_collector import LinuxProcessCollector
from agent.collectors.file_collector import LinuxFileCollector
from agent.collectors.network_collector import LinuxNetworkCollector
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData

class LinuxAgentManager:
    """Linux Agent Manager - Platform-specific implementation"""
    
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
        self.agent_id_file = os.path.join(os.path.dirname(__file__), 'agent_id.txt')
        self.agent_id = self._load_agent_id()
        self.is_registered = False
        
        # Linux system information
        self.system_info = self._get_linux_system_info()
        
        # Communication and processing
        self.communication = None
        self.event_processor = None
        
        # Data collectors
        self.collectors = {}
        
        # Performance tracking
        self.start_time = None
        self.last_heartbeat = None
        
        # Linux-specific settings
        self.requires_root = True
        self.has_root_privileges = os.geteuid() == 0
        
        self.logger.info(f"🐧 Linux Agent Manager initialized")
        self.logger.info(f"   📊 System: {self.system_info.get('distribution', 'Unknown')} {self.system_info.get('version', '')}")
        self.logger.info(f"   🔒 Root privileges: {self.has_root_privileges}")
    
    def _get_linux_system_info(self) -> Dict[str, str]:
        """Get comprehensive Linux system information"""
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
        """Initialize Linux agent manager and components"""
        try:
            self.logger.info("🚀 Starting Linux Agent Manager initialization...")
            
            # Check system requirements
            await self._check_linux_requirements()
            
            # Initialize server communication
            try:
                self.logger.info("📡 Initializing server communication...")
                self.communication = ServerCommunication(self.config_manager)
                await self.communication.initialize()
                self.logger.info("✅ Server communication initialized")
            except Exception as e:
                self.logger.error(f"❌ Server communication initialization failed: {e}")
                raise Exception(f"Server communication failed: {e}")
            
            # Initialize event processor
            try:
                self.logger.info("⚙️ Initializing event processor...")
                self.event_processor = EventProcessor(self.config_manager, self.communication)
                self.logger.info("✅ Event processor initialized")
            except Exception as e:
                self.logger.error(f"❌ Event processor initialization failed: {e}")
                raise Exception(f"Event processor failed: {e}")
            
            # Initialize Linux-specific collectors
            try:
                self.logger.info("📊 Initializing Linux data collectors...")
                await self._initialize_linux_collectors()
                self.logger.info("✅ Linux data collectors initialized")
            except Exception as e:
                self.logger.error(f"❌ Linux collector initialization failed: {e}")
                raise Exception(f"Linux collector initialization failed: {e}")
            
            self.is_initialized = True
            self.logger.info("🎉 Linux agent manager initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent manager initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")
            raise Exception(f"Linux agent manager initialization failed: {e}")
    
    async def _check_linux_requirements(self):
        """Check Linux-specific requirements"""
        try:
            self.logger.info("🔍 Checking Linux system requirements...")
            
            # Check root privileges
            if self.requires_root and not self.has_root_privileges:
                self.logger.warning("⚠️ Linux agent running without root privileges - monitoring may be limited")
            else:
                self.logger.info("✅ Root privileges available")
            
            # Check critical filesystem access
            critical_paths = ['/proc', '/sys', '/etc']
            for path in critical_paths:
                if not os.path.exists(path):
                    self.logger.warning(f"⚠️ Critical path not available: {path}")
                elif not os.access(path, os.R_OK):
                    self.logger.warning(f"⚠️ Cannot read critical path: {path}")
                else:
                    self.logger.debug(f"✅ Access to {path}")
            
            # Check for monitoring tools
            tools_to_check = ['ps', 'netstat', 'ss', 'lsof']
            available_tools = []
            for tool in tools_to_check:
                if self._check_tool_available(tool):
                    available_tools.append(tool)
            
            self.logger.info(f"✅ Available monitoring tools: {available_tools}")
            
            # Check psutil functionality
            try:
                psutil.process_iter()
                psutil.net_connections()
                self.logger.info("✅ psutil functionality verified")
            except Exception as e:
                self.logger.warning(f"⚠️ psutil limited functionality: {e}")
            
        except Exception as e:
            self.logger.error(f"❌ Linux requirements check failed: {e}")
            raise
    
    def _check_tool_available(self, tool_name: str) -> bool:
        """Check if a system tool is available"""
        try:
            import subprocess
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    async def _initialize_linux_collectors(self):
        """Initialize Linux-specific data collectors"""
        try:
            config = self.config_manager.get_config()
            collection_config = config.get('collection', {})
            
            # Process collector
            if collection_config.get('collect_processes', True):
                try:
                    self.logger.info("🔄 Initializing Linux Process Collector...")
                    self.collectors['process'] = LinuxProcessCollector(self.config_manager)
                    self.collectors['process'].set_event_processor(self.event_processor)
                    await self.collectors['process'].initialize()
                    self.logger.info("✅ Linux process collector initialized")
                except Exception as e:
                    self.logger.error(f"❌ Linux process collector initialization failed: {e}")
            
            # File collector
            if collection_config.get('collect_files', True):
                try:
                    self.logger.info("📁 Initializing Linux File Collector...")
                    self.collectors['file'] = LinuxFileCollector(self.config_manager)
                    self.collectors['file'].set_event_processor(self.event_processor)
                    await self.collectors['file'].initialize()
                    self.logger.info("✅ Linux file collector initialized")
                except Exception as e:
                    self.logger.error(f"❌ Linux file collector initialization failed: {e}")
            
            # Network collector
            if collection_config.get('collect_network', True):
                try:
                    self.logger.info("🌐 Initializing Linux Network Collector...")
                    self.collectors['network'] = LinuxNetworkCollector(self.config_manager)
                    self.collectors['network'].set_event_processor(self.event_processor)
                    await self.collectors['network'].initialize()
                    self.logger.info("✅ Linux network collector initialized")
                except Exception as e:
                    self.logger.error(f"❌ Linux network collector initialization failed: {e}")
            
            # TODO: Add more Linux-specific collectors
            # - Authentication collector (using auth.log, wtmp, utmp)
            # - System collector (using systemd, services, etc.)
            # - Container collector (Docker, Podman)
            # - Audit collector (auditd integration)
            
            self.logger.info(f"🎉 {len(self.collectors)} Linux collectors initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Linux collector initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full collector error details:\n{traceback.format_exc()}")
            raise
    
    async def start(self):
        """Start the Linux agent"""
        try:
            self.logger.info("🚀 Starting Linux agent...")
            
            # Register with server
            await self._register_with_server()
            
            # Ensure agent_id is available
            if not self.agent_id:
                raise Exception("Linux agent registration failed - no agent_id received")
            
            # Set agent_id for event processor
            if self.event_processor and self.agent_id:
                self.event_processor.set_agent_id(self.agent_id)
                self.logger.info(f"[EVENT_PROCESSOR] Set AgentID: {self.agent_id}")
            
            # Start event processor
            await self.event_processor.start()
            
            # Set agent_id on all collectors
            for name, collector in self.collectors.items():
                if hasattr(collector, 'set_agent_id'):
                    collector.set_agent_id(self.agent_id)
                    self.logger.debug(f"[{name.upper()}_COLLECTOR] Set AgentID: {self.agent_id}")
            
            # Start collectors
            await self._start_collectors()
            
            # Start monitoring
            self.is_running = True
            self.is_monitoring = True
            self.start_time = datetime.now()
            
            # Start heartbeat task
            asyncio.create_task(self._heartbeat_loop())
            
            # Start Linux-specific monitoring tasks
            asyncio.create_task(self._linux_system_monitor())
            
            self.logger.info(f"✅ Linux agent started successfully")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   📊 Collectors: {list(self.collectors.keys())}")
            self.logger.info(f"   🐧 Platform: Linux ({self.system_info.get('distribution', 'Unknown')})")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent start failed: {e}")
            raise
    
    async def stop(self):
        """Stop the Linux agent gracefully"""
        try:
            self.logger.info("🛑 Stopping Linux agent gracefully...")
            self.is_monitoring = False
            self.is_running = False
            
            # Stop collectors first
            await self._stop_collectors()
            
            # Stop event processor
            if self.event_processor:
                await self.event_processor.stop()
            
            # Send final heartbeat
            if self.is_registered:
                try:
                    await self._send_heartbeat(status='Offline')
                except:
                    pass
            
            self.logger.info("✅ Linux agent stopped gracefully")
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent stop error: {e}")
    
    async def pause(self):
        """Pause Linux agent monitoring"""
        try:
            if not self.is_paused:
                self.is_paused = True
                self.logger.info("⏸️ Linux agent monitoring PAUSED")
                
                # Pause all collectors
                for name, collector in self.collectors.items():
                    try:
                        if hasattr(collector, 'pause'):
                            await collector.pause()
                        self.logger.debug(f"⏸️ Paused {name} collector")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to pause {name} collector: {e}")
                
                # Send pause status
                if self.is_registered:
                    try:
                        await self._send_heartbeat(status='Paused')
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"❌ Linux agent pause error: {e}")
    
    async def resume(self):
        """Resume Linux agent monitoring"""
        try:
            if self.is_paused:
                self.is_paused = False
                self.logger.info("▶️ Linux agent monitoring RESUMED")
                
                # Resume all collectors
                for name, collector in self.collectors.items():
                    try:
                        if hasattr(collector, 'resume'):
                            await collector.resume()
                        self.logger.debug(f"▶️ Resumed {name} collector")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to resume {name} collector: {e}")
                
                # Send active status
                if self.is_registered:
                    try:
                        await self._send_heartbeat(status='Active')
                    except:
                        pass
        except Exception as e:
            self.logger.error(f"❌ Linux agent resume error: {e}")
    
    async def _register_with_server(self):
        """Register Linux agent with EDR server"""
        try:
            self.logger.info("📡 Registering Linux agent with EDR server...")
            
            # Create registration data
            registration_data = AgentRegistrationData(
                hostname=self.system_info['hostname'],
                ip_address=self._get_local_ip(),
                operating_system=f"Linux {self.system_info.get('distribution', 'Unknown')} {self.system_info.get('version', '')}",
                os_version=self.system_info.get('kernel', 'Unknown'),
                architecture=self.system_info.get('architecture', 'Unknown'),
                agent_version='2.1.0-Linux',
                mac_address=self._get_mac_address(),
                domain=self._get_domain(),
                install_path=str(Path(__file__).resolve().parent.parent.parent)
            )
            
            # Send registration request
            response = await self.communication.register_agent(registration_data)
            
            if response and response.get('success'):
                self.agent_id = response.get('agent_id')
                self.is_registered = True
                self._save_agent_id(self.agent_id)
                
                self.logger.info(f"✅ Linux agent registered successfully: {self.agent_id}")
                self.logger.info(f"   🖥️ Hostname: {self.system_info['hostname']}")
                self.logger.info(f"   🐧 OS: Linux {self.system_info.get('distribution', 'Unknown')}")
                self.logger.info(f"   🔧 Kernel: {self.system_info.get('kernel', 'Unknown')}")
                
                # Update configuration with server settings
                if 'heartbeat_interval' in response:
                    self.config['agent']['heartbeat_interval'] = response['heartbeat_interval']
                    
            else:
                raise Exception("Linux agent registration failed")
                
        except Exception as e:
            self.logger.error(f"❌ Linux agent registration failed: {e}")
            raise
    
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
                return fqdn.split('.', 1)[1]
            
            # Try to read from /etc/domain
            if os.path.exists('/etc/domain'):
                with open('/etc/domain', 'r') as f:
                    domain = f.read().strip()
                    if domain:
                        return domain
            
            # Try to get from resolv.conf
            if os.path.exists('/etc/resolv.conf'):
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('domain '):
                            return line.split()[1].strip()
            
            return None
        except Exception as e:
            self.logger.debug(f"Could not get domain: {e}")
            return None
    
    def _load_agent_id(self) -> Optional[str]:
        """Load agent ID from file"""
        try:
            if os.path.exists(self.agent_id_file):
                with open(self.agent_id_file, 'r') as f:
                    agent_id = f.read().strip()
                    if agent_id:
                        return agent_id
        except Exception as e:
            self.logger.debug(f"Could not load agent ID: {e}")
        return None
    
    def _save_agent_id(self, agent_id: str):
        """Save agent ID to file"""
        try:
            os.makedirs(os.path.dirname(self.agent_id_file), exist_ok=True)
            with open(self.agent_id_file, 'w') as f:
                f.write(agent_id)
        except Exception as e:
            self.logger.error(f"Could not save agent ID: {e}")
    
    async def _start_collectors(self):
        """Start all Linux collectors"""
        try:
            self.logger.info("🚀 Starting Linux collectors...")
            
            for name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'start'):
                        await collector.start()
                        self.logger.info(f"✅ {name} collector started")
                    else:
                        self.logger.warning(f"⚠️ {name} collector has no start method")
                except Exception as e:
                    self.logger.error(f"❌ Failed to start {name} collector: {e}")
            
            self.logger.info(f"🎉 {len(self.collectors)} Linux collectors started")
            
        except Exception as e:
            self.logger.error(f"❌ Linux collector start failed: {e}")
            raise
    
    async def _stop_collectors(self):
        """Stop all Linux collectors"""
        try:
            self.logger.info("🛑 Stopping Linux collectors...")
            
            for name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'stop'):
                        await collector.stop()
                        self.logger.info(f"✅ {name} collector stopped")
                    else:
                        self.logger.warning(f"⚠️ {name} collector has no stop method")
                except Exception as e:
                    self.logger.error(f"❌ Failed to stop {name} collector: {e}")
            
            self.logger.info("✅ All Linux collectors stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Linux collector stop failed: {e}")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to server"""
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
            
            heartbeat_data = AgentHeartbeatData(
                agent_id=self.agent_id,
                status=status,
                timestamp=datetime.now().isoformat(),
                cpu_usage=cpu_percent,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                uptime=time.time() - psutil.boot_time(),
                collector_status=self._get_collector_status()
            )
            
            await self.communication.send_heartbeat(heartbeat_data)
            self.last_heartbeat = datetime.now()
            
        except Exception as e:
            self.logger.error(f"❌ Heartbeat send failed: {e}")
    
    def _get_collector_status(self) -> Dict[str, str]:
        """Get status of all collectors"""
        status = {}
        for name, collector in self.collectors.items():
            try:
                if hasattr(collector, 'get_status'):
                    status[name] = collector.get_status()
                else:
                    status[name] = 'Unknown'
            except:
                status[name] = 'Error'
        return status
    
    async def _linux_system_monitor(self):
        """Linux-specific system monitoring tasks"""
        try:
            self.logger.info("🔍 Starting Linux system monitor...")
            
            while self.is_running and not self.is_paused:
                try:
                    # Monitor system resources
                    await self._check_system_resources()
                    
                    # Monitor critical system files
                    await self._check_critical_files()
                    
                    # Monitor system services
                    await self._check_system_services()
                    
                    # Wait before next check
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Linux system monitor error: {e}")
                    await asyncio.sleep(30)
                    
        except asyncio.CancelledError:
            self.logger.info("🛑 Linux system monitor cancelled")
        except Exception as e:
            self.logger.error(f"❌ Linux system monitor failed: {e}")
    
    async def _check_system_resources(self):
        """Check system resource usage"""
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
            
            # Load average
            load_avg = os.getloadavg()
            if load_avg[0] > 5.0:  # 5-minute load average
                self.logger.warning(f"⚠️ High system load: {load_avg[0]}")
                
        except Exception as e:
            self.logger.debug(f"System resource check error: {e}")
    
    async def _check_critical_files(self):
        """Check critical system files for changes"""
        try:
            critical_files = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/hosts',
                '/etc/resolv.conf'
            ]
            
            for file_path in critical_files:
                if os.path.exists(file_path):
                    try:
                        # Check file modification time
                        stat = os.stat(file_path)
                        # TODO: Implement file change detection logic
                        pass
                    except Exception as e:
                        self.logger.debug(f"Could not check {file_path}: {e}")
                        
        except Exception as e:
            self.logger.debug(f"Critical files check error: {e}")
    
    async def _check_system_services(self):
        """Check critical system services"""
        try:
            # Check if auditd is running
            try:
                import subprocess
                result = subprocess.run(['systemctl', 'is-active', 'auditd'], 
                                      capture_output=True, timeout=5)
                if result.returncode != 0:
                    self.logger.warning("⚠️ auditd service is not running")
            except:
                pass
            
            # Check if rsyslog is running
            try:
                result = subprocess.run(['systemctl', 'is-active', 'rsyslog'], 
                                      capture_output=True, timeout=5)
                if result.returncode != 0:
                    self.logger.warning("⚠️ rsyslog service is not running")
            except:
                pass
                
        except Exception as e:
            self.logger.debug(f"System services check error: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current agent status"""
        return {
            'agent_id': self.agent_id,
            'is_initialized': self.is_initialized,
            'is_running': self.is_running,
            'is_monitoring': self.is_monitoring,
            'is_paused': self.is_paused,
            'is_registered': self.is_registered,
            'system_info': self.system_info,
            'collectors': list(self.collectors.keys()),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'has_root_privileges': self.has_root_privileges
        }
    
    def get_collector_status(self) -> Dict[str, Any]:
        """Get detailed collector status"""
        status = {}
        for name, collector in self.collectors.items():
            try:
                if hasattr(collector, 'get_status'):
                    status[name] = collector.get_status()
                else:
                    status[name] = {'status': 'Unknown'}
            except Exception as e:
                status[name] = {'status': 'Error', 'error': str(e)}
        return status