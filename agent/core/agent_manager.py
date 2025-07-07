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
from collections import deque

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

# Import communication polling action queue
from .communication import polling_action_queue

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
        
        # Action queue polling
        self.action_polling_task = None
        self.action_polling_enabled = True
        
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
                syslog.openlog("edr-agent", syslog.LOG_PID, syslog.LOG_SECURITY)
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
        """🚀 Start the enhanced Linux agent manager with action queue support"""
        try:
            self.logger.info("🚀 Starting Enhanced Linux Agent Manager...")
            
            # Register with server
            await self._register_with_server()
            
            # FIXED: Ensure agent_id is available
            if not self.agent_id:
                raise Exception("Agent registration failed - no agent_id received")
            
            # Set agent_id for event processor
            if self.event_processor and self.agent_id:
                self.event_processor.set_agent_id(self.agent_id)
                self.logger.info(f"[EVENT_PROCESSOR] Set AgentID: {self.agent_id}")
            
            # Check alert endpoints
            await self._check_alert_endpoints_availability()
            
            # Start event processor
            await self.event_processor.start()
            
            # FIXED: Set agent_id on all collectors before starting
            for name, collector in self.collectors.items():
                if hasattr(collector, 'set_agent_id'):
                    collector.set_agent_id(self.agent_id)
                    self.logger.debug(f"[{name.upper()}_COLLECTOR] Set AgentID: {self.agent_id}")
            
            # Start collectors
            await self._start_collectors()
            
            # Start monitoring
            self.is_monitoring = True
            
            # Start heartbeat task
            asyncio.create_task(self._heartbeat_loop())
            
            # Start server connection monitor task
            asyncio.create_task(self.monitor_server_connection())
            
            # ✅ NEW: Start action queue polling
            await self._start_action_queue_polling()
            
            self.logger.info(f"[START] Using AgentID: {self.agent_id}")
            self.logger.info("Agent started successfully")
            
        except Exception as e:
            self.logger.error(f"Agent start failed: {e}")
            raise
    
    async def _start_action_queue_polling(self):
        """✅ NEW: Start polling action queue from Redis"""
        try:
            if not self.agent_id:
                self.logger.warning("⚠️ No agent_id available - cannot start action queue polling")
                return
            
            if not self.action_polling_enabled:
                self.logger.info("ℹ️ Action queue polling disabled")
                return
            
            # Start action queue polling in a separate thread
            def start_polling():
                try:
                    self.logger.info(f"🔄 Starting action queue polling for agent: {self.agent_id}")
                    polling_action_queue(self.agent_id)
                except Exception as e:
                    self.logger.error(f"❌ Action queue polling failed: {e}")
            
            # Create and start polling thread
            polling_thread = threading.Thread(
                target=start_polling,
                name=f"action-polling-{self.agent_id}",
                daemon=True
            )
            polling_thread.start()
            
            self.action_polling_task = polling_thread
            self.logger.info("✅ Action queue polling started")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start action queue polling: {e}")
    
    async def stop(self):
        """🛑 Stop the agent manager with proper cleanup"""
        try:
            self.logger.info("🛑 Stopping Enhanced Linux Agent Manager...")
            
            # Stop action queue polling
            if self.action_polling_task and self.action_polling_task.is_alive():
                self.logger.info("🛑 Stopping action queue polling...")
                # Note: polling_action_queue runs in infinite loop, will stop when agent stops
                self.action_polling_enabled = False
            
            # Stop event processor
            if self.event_processor:
                await self.event_processor.stop()
            
            # Stop collectors
            for name, collector in self.collectors.items():
                try:
                    await collector.stop()
                    self.logger.info(f"✅ {name} collector stopped")
                except Exception as e:
                    self.logger.error(f"❌ Error stopping {name} collector: {e}")
            
            # Stop communication
            if self.communication:
                await self.communication.close()
            
            self.is_running = False
            self.is_monitoring = False
            
            self.logger.info("✅ Enhanced Linux Agent Manager stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping agent manager: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """✅ ENHANCED: Get enhanced agent status with alert processing info"""
        return self.get_enhanced_status()
    
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