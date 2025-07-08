# agent/core/agent_manager.py - ENHANCED với Alert Processing
"""
Enhanced Linux Agent Manager với xử lý alerts từ server
Thêm khả năng nhận và xử lý security alerts từ EDR server
"""

import asyncio
import logging
import time
import uuid
import platform
import psutil
import os
import pwd
import threading
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

# ✅ ENHANCED: Import alert notification system
from agent.utils.security_notifications import (
    LinuxSecurityNotifier, 
    initialize_linux_notifier,
    get_linux_notifier
)

class EnhancedLinuxAgentManager:
    """Enhanced Linux Agent Manager với Alert Processing và Real-time Notifications"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Enhanced state management
        self.requires_root = True
        self.has_root_privileges = self._check_root_privileges()
        self.is_initialized = False
        self.is_running = False
        self.is_monitoring = False
        self.is_paused = False
        self.is_registered = False
        self.start_time = None
        self.last_heartbeat = None
        
        # Enhanced agent ID management
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
        
        # ✅ ENHANCED: Security notification system
        self.security_notifier = None
        self.alert_handler_registered = False
        
        # ✅ ENHANCED: Alert processing statistics
        self.alert_stats = {
            'total_alerts_received': 0,
            'server_rule_alerts': 0,
            'local_rule_alerts': 0,
            'critical_alerts': 0,
            'high_alerts': 0,
            'medium_alerts': 0,
            'low_alerts': 0,
            'alerts_acknowledged': 0,
            'last_alert_time': None,
            'alert_processing_errors': 0
        }
        
        # Performance monitoring
        self.performance_stats = {
            'events_processed': 0,
            'collector_errors': 0,
            'memory_usage_mb': 0,
            'cpu_usage_percent': 0,
            'last_performance_check': time.time(),
            'logs_sent': 0,
            'logs_failed': 0,
            'realtime_streams_active': 0
        }
        
        # Health monitoring
        self.health_checks = {
            'communication': True,
            'event_processor': True,
            'collectors': {},
            'security_notifier': True,  # ✅ ENHANCED: Alert system health
            'alert_processing': True,   # ✅ ENHANCED: Alert processing health
            'last_health_check': time.time()
        }
        
        # System stats
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
        
        self.logger.info(f"🚨 Enhanced Linux Agent Manager initialized with Alert Processing")
        self.logger.info(f"🔐 Root privileges: {self.has_root_privileges}")
        self.logger.info(f"🔔 Alert notifications enabled: True")
        self.logger.info(f"🆔 Agent ID: {self.agent_id[:8]}...")
    
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
                'is_root': 'False'
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
        """✅ ENHANCED: Initialize Linux Agent Manager with alert processing"""
        try:
            self.logger.info("🚀 Starting Enhanced Linux Agent Manager initialization...")
            
            await self._check_system_requirements()
            
            # ✅ ENHANCED: Initialize Security Notification System FIRST
            await self._initialize_security_notifications()
            
            # Initialize Communication with alert handling
            await self._initialize_communication_with_retries()
            
            # Initialize Event Processor
            await self._initialize_event_processor()
            
            # Initialize Collectors with selective enabling
            await self._initialize_collectors_optimized()
            
            self.is_initialized = True
            self.logger.info("🎉 Enhanced Linux Agent Manager initialization completed successfully")
            self.logger.info("🔔 Alert processing system ready")
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced Linux agent manager initialization failed: {e}")
            import traceback
            self.logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")
            raise Exception(f"Enhanced Linux agent manager initialization failed: {e}")
    
    async def _initialize_security_notifications(self):
        """✅ ENHANCED: Initialize security notification system"""
        try:
            self.logger.info("🔔 Initializing Security Notification System...")
            
            # Initialize the Linux security notifier
            self.security_notifier = initialize_linux_notifier(self.config_manager)
            
            if self.security_notifier:
                # Test notification capabilities
                notifier_stats = self.security_notifier.get_stats()
                self.logger.info("✅ Security Notification System initialized:")
                self.logger.info(f"   🖥️ Desktop: {notifier_stats.get('desktop_environment', 'Unknown')}")
                self.logger.info(f"   🔔 Methods: {notifier_stats.get('notification_methods', [])}")
                self.logger.info(f"   🔊 Sound: {notifier_stats.get('sound_enabled', False)}")
                self.logger.info(f"   📺 Display: {notifier_stats.get('display_available', False)}")
                
                self.health_checks['security_notifier'] = True
            else:
                self.logger.warning("⚠️ Security notification system not available")
                self.health_checks['security_notifier'] = False
            
        except Exception as e:
            self.logger.error(f"❌ Security notification initialization failed: {e}")
            self.health_checks['security_notifier'] = False
    
    async def _initialize_communication_with_retries(self):
        """✅ ENHANCED: Initialize communication with alert handler registration"""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                self.logger.info("📡 Initializing Enhanced Server Communication...")
                self.communication = ServerCommunication(self.config_manager)
                await self.communication.initialize()
                self.logger.info("✅ Server Communication initialized")
                
                # ✅ ENHANCED: Register alert handler
                await self._register_alert_handler()
                
                # Test connectivity
                self.logger.info("🔍 Testing server connectivity...")
                if await self.communication.test_server_connection():
                    self.logger.info("✅ Server connection test passed")
                    return  # Success - exit the retry loop
                else:
                    self.logger.warning(f"⚠️ Server connection test failed (attempt {attempt + 1}/{max_retries})")
                    
            except Exception as e:
                self.logger.warning(f"❌ Communication attempt {attempt + 1} failed: {e}")
                
                if attempt < max_retries - 1:
                    self.logger.info(f"⏳ Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    # All attempts failed - continue in offline mode
                    self.logger.warning("⚠️ Communication initialization failed - agent will run in offline mode")
                    self.logger.info("💡 Agent will continue running and retry connection periodically")
                    return  # Don't raise exception - allow agent to continue
        
        # If we get here, all retries failed but we should continue
        self.logger.warning("⚠️ Communication initialization failed - agent will run in offline mode")
    
    async def _register_alert_handler(self):
        """✅ ENHANCED: Register alert handler with communication system"""
        try:
            if self.communication and self.security_notifier:
                # Set communication reference in security notifier
                self.security_notifier.set_communication(self.communication)
                
                # Add our enhanced alert handler
                self.communication.add_alert_handler(self._enhanced_alert_handler)
                
                self.alert_handler_registered = True
                self.health_checks['alert_processing'] = True
                
                self.logger.info("✅ Enhanced alert handler registered with communication system")
                self.logger.info("🔔 Agent ready to receive and process security alerts from server")
            else:
                self.logger.warning("⚠️ Cannot register alert handler - missing communication or notifier")
                self.health_checks['alert_processing'] = False
                
        except Exception as e:
            self.logger.error(f"❌ Failed to register alert handler: {e}")
            self.health_checks['alert_processing'] = False
    
    async def _enhanced_alert_handler(self, security_alert):
        """✅ ENHANCED: Enhanced alert handler for processing security alerts"""
        try:
            self.logger.warning(f"🚨 ENHANCED ALERT HANDLER PROCESSING:")
            self.logger.warning(f"   🆔 Alert ID: {security_alert.alert_id}")
            self.logger.warning(f"   📋 Type: {security_alert.alert_type}")
            self.logger.warning(f"   ⚠️ Severity: {security_alert.severity}")
            self.logger.warning(f"   📊 Risk Score: {security_alert.risk_score}")
            self.logger.warning(f"   📝 Rule: {security_alert.rule_name}")
            
            # Update alert statistics
            self._update_alert_statistics(security_alert)
            
            # Process alert through security notifier
            if self.security_notifier:
                await self.security_notifier.handle_security_alert(security_alert)
                self.logger.info("✅ Alert processed through security notification system")
            else:
                self.logger.warning("⚠️ No security notifier available - showing basic alert")
                await self._show_basic_alert(security_alert)
            
            # Log alert to system for audit trail
            await self._log_alert_to_system(security_alert)
            
            # Check if alert requires immediate action
            if security_alert.action_required or security_alert.severity == 'Critical':
                await self._handle_critical_alert(security_alert)
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced alert handler error: {e}")
            self.alert_stats['alert_processing_errors'] += 1
    
    def _update_alert_statistics(self, security_alert):
        """✅ ENHANCED: Update alert processing statistics"""
        try:
            self.alert_stats['total_alerts_received'] += 1
            self.alert_stats['last_alert_time'] = datetime.now()
            
            # Update by severity
            severity = security_alert.severity.lower()
            if severity == 'critical':
                self.alert_stats['critical_alerts'] += 1
            elif severity == 'high':
                self.alert_stats['high_alerts'] += 1
            elif severity == 'medium':
                self.alert_stats['medium_alerts'] += 1
            elif severity == 'low':
                self.alert_stats['low_alerts'] += 1
            
            # Update by type
            if 'server' in security_alert.rule_name.lower():
                self.alert_stats['server_rule_alerts'] += 1
            else:
                self.alert_stats['local_rule_alerts'] += 1
            
        except Exception as e:
            self.logger.debug(f"Error updating alert statistics: {e}")
    
    async def _show_basic_alert(self, security_alert):
        """✅ ENHANCED: Show basic alert when no notifier available"""
        try:
            print("\n" + "=" * 80)
            print("🚨 LINUX SECURITY ALERT")
            print("=" * 80)
            print(f"🕒 Time: {security_alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"🏷️ Alert ID: {security_alert.alert_id}")
            print(f"⚠️ Severity: {security_alert.severity}")
            print(f"📊 Risk Score: {security_alert.risk_score}/100")
            print(f"📝 Rule: {security_alert.rule_name}")
            print(f"📋 Description: {security_alert.rule_description}")
            print(f"🔍 Threat: {security_alert.threat_description}")
            print("=" * 80)
            print("🔧 RECOMMENDED ACTIONS:")
            print("1. ✅ Investigate immediately")
            print("2. 📋 Check system logs for related activity")
            print("3. 🔍 Monitor system for additional suspicious behavior")
            print("4. 📞 Contact security team if needed")
            print("=" * 80)
            
        except Exception as e:
            self.logger.error(f"❌ Error showing basic alert: {e}")
    
    async def _log_alert_to_system(self, security_alert):
        """✅ ENHANCED: Log alert to system for audit trail"""
        try:
            # Log to syslog if available
            import syslog
            try:
                syslog.openlog("edr-agent", syslog.LOG_PID, syslog.LOG_AUTH)
                syslog.syslog(syslog.LOG_WARNING, 
                    f"SECURITY ALERT: {security_alert.rule_name} - "
                    f"Severity: {security_alert.severity} - "
                    f"Risk: {security_alert.risk_score}/100"
                )
                syslog.closelog()
            except:
                pass
            
            # Log to application log
            self.logger.warning(f"🚨 SECURITY ALERT AUDIT LOG:")
            self.logger.warning(f"   Alert ID: {security_alert.alert_id}")
            self.logger.warning(f"   Rule: {security_alert.rule_name}")
            self.logger.warning(f"   Severity: {security_alert.severity}")
            self.logger.warning(f"   Risk Score: {security_alert.risk_score}")
            self.logger.warning(f"   Timestamp: {security_alert.timestamp}")
            
            # Write to dedicated alert log file
            try:
                alert_log_file = Path("logs/security_alerts.log")
                alert_log_file.parent.mkdir(exist_ok=True)
                
                with open(alert_log_file, 'a', encoding='utf-8') as f:
                    f.write(f"{datetime.now().isoformat()} - ALERT - "
                           f"ID:{security_alert.alert_id} - "
                           f"Rule:{security_alert.rule_name} - "
                           f"Severity:{security_alert.severity} - "
                           f"Risk:{security_alert.risk_score}\n")
            except Exception as e:
                self.logger.debug(f"Could not write to alert log file: {e}")
                
        except Exception as e:
            self.logger.error(f"❌ Error logging alert to system: {e}")
    
    async def _handle_critical_alert(self, security_alert):
        """✅ ENHANCED: Handle critical alerts requiring immediate action"""
        try:
            self.logger.critical(f"🚨 CRITICAL ALERT HANDLING: {security_alert.rule_name}")
            
            # For critical alerts, also send system-wide notification
            if security_alert.severity == 'Critical':
                try:
                    # Use wall command to send message to all terminals
                    critical_message = f"""
🚨 CRITICAL SECURITY ALERT 🚨
Rule: {security_alert.rule_name}
Risk Score: {security_alert.risk_score}/100
Time: {security_alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

IMMEDIATE ACTION REQUIRED
Contact your system administrator immediately.
"""
                    subprocess.run(['wall', critical_message], 
                                 input=critical_message, text=True, timeout=5)
                except Exception as e:
                    self.logger.debug(f"Could not send wall message: {e}")
            
            # Log critical alert with high priority
            self.logger.critical(f"🚨 CRITICAL SECURITY THREAT DETECTED:")
            self.logger.critical(f"   🏷️ Rule: {security_alert.rule_name}")
            self.logger.critical(f"   📊 Risk Score: {security_alert.risk_score}/100")
            self.logger.critical(f"   🔍 Threat: {security_alert.threat_description}")
            self.logger.critical(f"   ⚠️ ACTION REQUIRED: Immediate investigation needed")
            
        except Exception as e:
            self.logger.error(f"❌ Error handling critical alert: {e}")
    
    async def _initialize_event_processor(self):
        """Initialize Event Processor with validation"""
        try:
            self.logger.info("⚙️ Initializing Event Processor...")
            if self.communication is None:
                raise Exception("Communication not initialized")
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
            
            if cpu_count is not None and cpu_count < 2:
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
        """✅ ENHANCED: Start Linux Agent Manager with alert processing"""
        try:
            self.logger.info("🚀 Starting Enhanced Linux Agent Manager with Alert Processing...")
            
            # Register with server if not already registered
            if not self.is_registered:
                registration_success = await self._register_with_server()
                if not registration_success:
                    self.logger.warning("⚠️ Registration failed - agent will run in offline mode")
                    # Generate a temporary agent ID for offline operation
                    if not self.agent_id:
                        self.agent_id = f"offline-{uuid.uuid4().hex[:8]}"
                        self.logger.info(f"🆔 Using temporary agent ID: {self.agent_id}")
            
            # Ensure agent_id is available (either from registration or temporary)
            if not self.agent_id:
                self.logger.error("❌ No agent_id available - cannot start agent")
                return
            
            self.logger.info(f"✅ Agent ready with ID: {self.agent_id}")
            
            # Update agent_id everywhere after successful registration or temporary assignment
            await self._update_all_agent_ids()
            
            # Start Event Processor
            self.logger.info("⚡ Starting Event Processor...")
            if self.event_processor is not None and hasattr(self.event_processor, 'start'):
            await self.event_processor.start()
                self.logger.info("✅ Event Processor started")
            else:
                self.logger.warning("⚠️ Event Processor not available")
            
            # ✅ ENHANCED: Start alert polling if communication is available
            await self._start_alert_monitoring()
            
            # Start collectors with error handling
            await self._start_collectors_safely()
            
            # Set final running state
            self.is_running = True
            self.is_monitoring = True
            self.start_time = datetime.now()
            
            # Start enhanced monitoring tasks with alert monitoring
            asyncio.create_task(self._heartbeat_loop())
            asyncio.create_task(self._system_monitor())
            asyncio.create_task(self._performance_monitor())
            asyncio.create_task(self._health_monitor())
            asyncio.create_task(self._alert_monitoring_loop())  # ✅ ENHANCED: Alert monitoring
            
            self.logger.info(f"🎉 Enhanced Linux Agent Manager started successfully")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   📊 Active Collectors: {len(self.collectors)}")
            self.logger.info(f"   🔔 Alert Processing: {self.alert_handler_registered}")
            self.logger.info(f"   🚨 Security Notifications: {bool(self.security_notifier)}")
            self.logger.info(f"   🐧 Platform: Linux ({self.system_info.get('distribution', 'Unknown')})")
            
            if not self.is_registered:
                self.logger.info("💡 Agent running in offline mode - will retry registration periodically")
            
        except Exception as e:
            self.logger.error(f"❌ Enhanced Linux agent manager start failed: {e}")
            raise
    
    async def _start_alert_monitoring(self):
        """✅ ENHANCED: Start alert monitoring and polling"""
        try:
            if self.communication and hasattr(self.communication, 'start_alert_polling'):
                await self.communication.start_alert_polling()
                self.logger.info("✅ Alert polling started")
            else:
                self.logger.warning("⚠️ Alert polling not available - communication offline")
                
        except Exception as e:
            self.logger.error(f"❌ Error starting alert monitoring: {e}")
    
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
        """Register with server with enhanced data collection - FIXED"""
        try:
            if self.is_registered and self.agent_id:
                self.logger.info(f"✅ Agent already registered with ID: {self.agent_id[:8]}...")
                return True
            
            # Check if communication is available
            if not self.communication or not self.communication.is_online():
                self.logger.warning("⚠️ Communication not available - skipping registration")
                self.logger.info("💡 Agent will run in offline mode and retry registration later")
                return False
            
            self.logger.info("📡 Registering Enhanced Linux Agent with alert capabilities...")
            
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
                agent_version='2.1.0-Linux-ENHANCED-ALERTS',
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
                has_root_privileges=self.system_info.get('is_root', 'False') == 'True'
            )
            
            # Log registration details
            self.logger.info(f"📋 Enhanced Registration Details:")
            self.logger.info(f"   🆔 Agent ID: {self.agent_id}")
            self.logger.info(f"   🖥️ Hostname: {registration_data.hostname}")
            self.logger.info(f"   🌐 IP Address: {registration_data.ip_address}")
            self.logger.info(f"   🐧 OS: {registration_data.operating_system}")
            self.logger.info(f"   🔔 Alert Capable: YES")
            self.logger.info(f"   🚨 Notification Ready: {bool(self.security_notifier)}")
            
            # Register agent with server
            self.logger.info("📝 Registering enhanced agent with server...")
            registration_result = await self.communication.register_agent(registration_data)
            
            if registration_result and (registration_result.get('success') or registration_result.get('agent_id')):
                returned_agent_id = registration_result.get('agent_id')
                if returned_agent_id:
                    self.agent_id = returned_agent_id
                    self.is_registered = True
                    self.logger.info(f"✅ Enhanced agent registered successfully: {self.agent_id}")
                    self.logger.info("🔔 Agent ready to receive security alerts from server")
                    return True
                else:
                    self.logger.warning("⚠️ Registration successful but no agent_id returned")
                    return False
            else:
                error_msg = registration_result.get('error', 'Unknown error') if registration_result else 'No response'
                self.logger.warning(f"⚠️ Registration failed: {error_msg}")
                self.logger.info("💡 Agent will continue running and retry registration later")
                return False
            
        except Exception as e:
            self.logger.warning(f"⚠️ Registration failed: {e}")
            self.logger.info("💡 Agent will continue running and retry registration later")
            return False  # Don't raise exception - allow agent to continue
    
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
                if hasattr(self.communication, 'set_agent_id'):
                    self.communication.set_agent_id(self.agent_id)
                    self.logger.debug("✅ Communication agent_id updated")
            
            self.logger.info("✅ All components updated with new agent_id")
            
        except Exception as e:
            self.logger.error(f"❌ Error updating agent_ids: {e}")
    
    async def _alert_monitoring_loop(self):
        """✅ ENHANCED: Monitor alert processing health and statistics"""
        try:
            while self.is_running and not self.is_paused:
                try:
                    # Check alert processing health
                    if self.communication and hasattr(self.communication, 'get_stats'):
                        comm_stats = self.communication.get_stats()
                        
                        # Update alert statistics from communication
                        self.alert_stats.update({
                            'total_alerts_received': comm_stats.get('alerts_received', 0),
                            'alerts_processed': comm_stats.get('alerts_processed', 0)
                        })
                    
                    # Check security notifier health
                    if self.security_notifier:
                        notifier_stats = self.security_notifier.get_stats()
                        self.health_checks['security_notifier'] = notifier_stats.get('enabled', False)
                    
                    # Log alert statistics every 5 minutes
                    if int(time.time()) % 300 == 0:
                        self._log_alert_statistics()
                    
                    # Check for stale alert processing
                    if (self.alert_stats['last_alert_time'] and 
                        (datetime.now() - self.alert_stats['last_alert_time']).total_seconds() > 3600):
                        self.logger.info("📊 No alerts received in the last hour")
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Alert monitoring error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ Alert monitoring loop failed: {e}")
    
    def _log_alert_statistics(self):
        """✅ ENHANCED: Log alert processing statistics"""
        try:
            self.logger.info("🚨 Alert Processing Statistics:")
            self.logger.info(f"   📥 Total Alerts Received: {self.alert_stats['total_alerts_received']}")
            self.logger.info(f"   🔴 Critical: {self.alert_stats['critical_alerts']}")
            self.logger.info(f"   🟠 High: {self.alert_stats['high_alerts']}")
            self.logger.info(f"   🟡 Medium: {self.alert_stats['medium_alerts']}")
            self.logger.info(f"   🟢 Low: {self.alert_stats['low_alerts']}")
            self.logger.info(f"   📊 Server Rules: {self.alert_stats['server_rule_alerts']}")
            self.logger.info(f"   📋 Local Rules: {self.alert_stats['local_rule_alerts']}")
            self.logger.info(f"   ✅ Acknowledged: {self.alert_stats['alerts_acknowledged']}")
            self.logger.info(f"   ❌ Processing Errors: {self.alert_stats['alert_processing_errors']}")
            
            if self.alert_stats['last_alert_time']:
                last_alert_ago = (datetime.now() - self.alert_stats['last_alert_time']).total_seconds()
                self.logger.info(f"   🕒 Last Alert: {last_alert_ago:.0f} seconds ago")
                
        except Exception as e:
            self.logger.debug(f"Error logging alert statistics: {e}")
    
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
        """Monitor agent performance"""
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
        """Monitor component health"""
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
                    
                    # ✅ ENHANCED: Check alert processing health
                    self.health_checks['alert_processing'] = self.alert_handler_registered
                    if self.security_notifier:
                        notifier_stats = self.security_notifier.get_stats()
                        self.health_checks['security_notifier'] = notifier_stats.get('enabled', False)
                    
                    # Log health summary every 5 minutes
                    if int(time.time()) % 300 == 0:
                        healthy_collectors = sum(1 for status in self.health_checks['collectors'].values() if status)
                        total_collectors = len(self.health_checks['collectors'])
                        
                        self.logger.info("🏥 Enhanced Health Status:")
                        self.logger.info(f"   📡 Communication: {'✅' if self.health_checks['communication'] else '❌'}")
                        self.logger.info(f"   ⚡ Event Processor: {'✅' if self.health_checks['event_processor'] else '❌'}")
                        self.logger.info(f"   📊 Collectors: {healthy_collectors}/{total_collectors} healthy")
                        self.logger.info(f"   🔔 Alert Processing: {'✅' if self.health_checks['alert_processing'] else '❌'}")
                        self.logger.info(f"   🚨 Security Notifier: {'✅' if self.health_checks['security_notifier'] else '❌'}")
                    
                    self.health_checks['last_health_check'] = time.time()
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"❌ Health monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self.logger.error(f"❌ Health monitor failed: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """✅ ENHANCED: Get enhanced agent status with alert processing info"""
        return self.get_enhanced_status()
    
    async def stop(self):
        """✅ ENHANCED: Stop the enhanced agent manager and all components"""
        try:
            self.logger.info("🛑 Stopping Enhanced Linux Agent Manager with Alert Processing...")
            self.is_running = False
            self.is_monitoring = False
            
            # ✅ ENHANCED: Stop alert polling
            if self.communication and hasattr(self.communication, 'stop_alert_polling'):
                await self.communication.stop_alert_polling()
                self.logger.info("✅ Alert polling stopped")
            
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
            
            # Close communication (includes stopping alert polling)
            if self.communication:
                try:
                await self.communication.close()
                    self.logger.info("✅ Communication closed")
                except Exception as e:
                    self.logger.error(f"❌ Error closing communication: {e}")
            
            # ✅ ENHANCED: Log final alert statistics
            if self.alert_stats['total_alerts_received'] > 0:
                self.logger.info("🚨 Final Alert Statistics:")
                self.logger.info(f"   📥 Total Alerts: {self.alert_stats['total_alerts_received']}")
                self.logger.info(f"   🔴 Critical: {self.alert_stats['critical_alerts']}")
                self.logger.info(f"   🟠 High: {self.alert_stats['high_alerts']}")
                self.logger.info(f"   ❌ Errors: {self.alert_stats['alert_processing_errors']}")
            
            self.logger.info("✅ Enhanced Linux Agent Manager stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping enhanced agent manager: {e}")
    
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
        """✅ ENHANCED: Send heartbeat to server with alert processing info"""
        try:
            if not self.is_registered or not self.agent_id:
                self.logger.debug("Skipping heartbeat - agent not registered")
                return
            
            # Get current system metrics
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # ✅ ENHANCED: Create heartbeat data with alert info
            heartbeat_data = AgentHeartbeatData(
                agent_id=self.agent_id,
                hostname=self.system_info['hostname'],
                timestamp=datetime.now().isoformat(),
                status="Active",
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_usage=disk.percent,
                uptime=time.time() - psutil.boot_time(),
                events_sent=self.performance_stats.get('events_processed', 0),
                collector_status=self._get_collector_status()
            )
            
            # ✅ ENHANCED: Add alert processing info to metadata
            if hasattr(heartbeat_data, 'metadata') and heartbeat_data.metadata:
                heartbeat_data.metadata.update({
                    'alert_processing': {
                        'handler_registered': self.alert_handler_registered,
                        'total_alerts_received': self.alert_stats['total_alerts_received'],
                        'critical_alerts': self.alert_stats['critical_alerts'],
                        'processing_errors': self.alert_stats['alert_processing_errors'],
                        'notifier_available': bool(self.security_notifier),
                        'last_alert_time': self.alert_stats['last_alert_time'].isoformat() if self.alert_stats['last_alert_time'] else None
                    }
                })
            
            # Send heartbeat
            if self.communication:
                await self.communication.send_heartbeat(heartbeat_data)
                self.last_heartbeat = datetime.now()
                self.logger.debug(f"💓 Enhanced heartbeat sent - CPU: {cpu_usage:.1f}%, Memory: {memory.percent:.1f}%, Alerts: {self.alert_stats['total_alerts_received']}")
            
        except Exception as e:
            self.logger.error(f"❌ Error sending enhanced heartbeat: {e}")
    
    async def pause(self):
        """Pause the agent manager"""
        try:
            self.logger.info("⏸️ Pausing Enhanced Linux Agent Manager...")
            self.is_paused = True
            
            # Pause collectors
            for name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'pause'):
                        await collector.pause()
                        self.logger.info(f"⏸️ {name} collector paused")
                except Exception as e:
                    self.logger.error(f"❌ Error pausing {name} collector: {e}")
            
            self.logger.info("✅ Enhanced Linux Agent Manager paused")
            
        except Exception as e:
            self.logger.error(f"❌ Error pausing agent manager: {e}")
    
    async def resume(self):
        """Resume the agent manager"""
        try:
            self.logger.info("▶️ Resuming Enhanced Linux Agent Manager...")
            self.is_paused = False
            
            # Resume collectors
            for name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'resume'):
                        await collector.resume()
                        self.logger.info(f"▶️ {name} collector resumed")
                except Exception as e:
                    self.logger.error(f"❌ Error resuming {name} collector: {e}")
            
            self.logger.info("✅ Enhanced Linux Agent Manager resumed")
            
        except Exception as e:
            self.logger.error(f"❌ Error resuming agent manager: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get current performance statistics"""
        return self.performance_stats.copy()
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status"""
        return self.health_checks.copy()
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """✅ ENHANCED: Get alert processing statistics"""
        return self.alert_stats.copy()
    
    def get_enhanced_status(self) -> Dict[str, Any]:
        """✅ ENHANCED: Get enhanced agent status with alert processing metrics"""
        status = {
            'agent_type': 'linux_enhanced_with_alerts',
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
            # Enhanced metrics
            'performance_stats': self.performance_stats,
            'health_checks': self.health_checks,
            # ✅ ENHANCED: Alert processing status
            'alert_processing': {
                'enabled': True,
                'handler_registered': self.alert_handler_registered,
                'notifier_available': bool(self.security_notifier),
                'statistics': self.alert_stats,
                'notifier_status': self.security_notifier.get_stats() if self.security_notifier else None
            },
            'version': '2.1.0-Enhanced-Alerts'
        }
        
        return status

# Backward compatibility alias
LinuxAgentManager = EnhancedLinuxAgentManager