# agent/service/systemd_service.py - Systemd Service Manager
"""
Systemd Service Manager - Install, manage, and monitor EDR agent as systemd service
Enhanced service management for Linux EDR agent
"""

import os
import sys
import subprocess
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

class SystemdServiceManager:
    """Systemd Service Manager for EDR Agent"""
    
    def __init__(self, agent_path: str = None):
        self.agent_path = agent_path or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.service_name = "edr-agent"
        self.service_file = f"/etc/systemd/system/{self.service_name}.service"
        self.service_description = "EDR Agent - Endpoint Detection and Response Agent"
        self.python_executable = sys.executable
        self.main_script = os.path.join(self.agent_path, "main.py")
        
        # Service configuration
        self.service_config = {
            'Type': 'notify',
            'Restart': 'always',
            'RestartSec': '10',
            'User': 'root',
            'Group': 'root',
            'WorkingDirectory': self.agent_path,
            'StandardOutput': 'journal',
            'StandardError': 'journal',
            'SyslogIdentifier': 'edr-agent',
            'KillMode': 'mixed',
            'KillSignal': 'SIGTERM',
            'TimeoutStopSec': '30',
            'LimitNOFILE': '65536',
            'LimitNPROC': '65536',
            'NoNewPrivileges': 'true',
            'ProtectSystem': 'strict',
            'ProtectHome': 'true',
            'ReadWritePaths': '/var/log /var/cache /tmp /var/tmp',
            'PrivateTmp': 'true',
            'PrivateDevices': 'true',
            'ProtectKernelTunables': 'true',
            'ProtectKernelModules': 'true',
            'ProtectControlGroups': 'true',
            'RestrictRealtime': 'true',
            'RestrictSUIDSGID': 'true',
            'LockPersonality': 'true',
            'MemoryDenyWriteExecute': 'true'
        }
    
    def check_systemd_available(self) -> bool:
        """Check if systemd is available on the system"""
        try:
            result = subprocess.run(
                ['systemctl', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Systemd check failed: {e}")
            return False
    
    def check_root_privileges(self) -> bool:
        """Check if running with root privileges"""
        return os.geteuid() == 0
    
    def create_service_file(self) -> bool:
        """Create systemd service file"""
        try:
            if not self.check_root_privileges():
                logger.error("❌ Root privileges required to create systemd service")
                return False
            
            # Create service file content
            service_content = self._generate_service_file()
            
            # Write service file
            with open(self.service_file, 'w') as f:
                f.write(service_content)
            
            logger.info(f"✅ Service file created: {self.service_file}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create service file: {e}")
            return False
    
    def _generate_service_file(self) -> str:
        """Generate systemd service file content"""
        service_content = f"""[Unit]
Description={self.service_description}
Documentation=https://github.com/edr-project/linux-agent
After=network.target auditd.service
Wants=network.target
Conflicts=shutdown.target

[Service]
Type={self.service_config['Type']}
User={self.service_config['User']}
Group={self.service_config['Group']}
WorkingDirectory={self.service_config['WorkingDirectory']}
ExecStart={self.python_executable} {self.main_script}
ExecReload=/bin/kill -HUP $MAINPID
Restart={self.service_config['Restart']}
RestartSec={self.service_config['RestartSec']}
StandardOutput={self.service_config['StandardOutput']}
StandardError={self.service_config['StandardError']}
SyslogIdentifier={self.service_config['SyslogIdentifier']}
KillMode={self.service_config['KillMode']}
KillSignal={self.service_config['KillSignal']}
TimeoutStopSec={self.service_config['TimeoutStopSec']}

# Resource limits
LimitNOFILE={self.service_config['LimitNOFILE']}
LimitNPROC={self.service_config['LimitNPROC']}

# Security settings
NoNewPrivileges={self.service_config['NoNewPrivileges']}
ProtectSystem={self.service_config['ProtectSystem']}
ProtectHome={self.service_config['ProtectHome']}
ReadWritePaths={self.service_config['ReadWritePaths']}
PrivateTmp={self.service_config['PrivateTmp']}
PrivateDevices={self.service_config['PrivateDevices']}
ProtectKernelTunables={self.service_config['ProtectKernelTunables']}
ProtectKernelModules={self.service_config['ProtectKernelModules']}
ProtectControlGroups={self.service_config['ProtectControlGroups']}
RestrictRealtime={self.service_config['RestrictRealtime']}
RestrictSUIDSGID={self.service_config['RestrictSUIDSGID']}
LockPersonality={self.service_config['LockPersonality']}
MemoryDenyWriteExecute={self.service_config['MemoryDenyWriteExecute']}

# Environment variables
Environment=PYTHONPATH={self.agent_path}
Environment=EDR_AGENT_PATH={self.agent_path}
Environment=EDR_AGENT_MODE=service

[Install]
WantedBy=multi-user.target
"""
        return service_content
    
    def install_service(self) -> bool:
        """Install EDR agent as systemd service"""
        try:
            if not self.check_systemd_available():
                logger.error("❌ Systemd not available on this system")
                return False
            
            if not self.check_root_privileges():
                logger.error("❌ Root privileges required to install service")
                return False
            
            logger.info("🔧 Installing EDR agent as systemd service...")
            
            # Create service file
            if not self.create_service_file():
                return False
            
            # Reload systemd daemon
            result = subprocess.run(
                ['systemctl', 'daemon-reload'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to reload systemd daemon: {result.stderr}")
                return False
            
            # Enable service
            result = subprocess.run(
                ['systemctl', 'enable', self.service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to enable service: {result.stderr}")
                return False
            
            logger.info("✅ EDR agent service installed successfully")
            logger.info(f"   Service name: {self.service_name}")
            logger.info(f"   Service file: {self.service_file}")
            logger.info("   Use 'systemctl start edr-agent' to start the service")
            logger.info("   Use 'systemctl status edr-agent' to check status")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Service installation failed: {e}")
            return False
    
    def uninstall_service(self) -> bool:
        """Uninstall EDR agent systemd service"""
        try:
            if not self.check_root_privileges():
                logger.error("❌ Root privileges required to uninstall service")
                return False
            
            logger.info("🗑️ Uninstalling EDR agent service...")
            
            # Stop service if running
            if self.is_service_running():
                self.stop_service()
            
            # Disable service
            result = subprocess.run(
                ['systemctl', 'disable', self.service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"⚠️ Failed to disable service: {result.stderr}")
            
            # Remove service file
            if os.path.exists(self.service_file):
                os.remove(self.service_file)
                logger.info(f"✅ Removed service file: {self.service_file}")
            
            # Reload systemd daemon
            result = subprocess.run(
                ['systemctl', 'daemon-reload'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"⚠️ Failed to reload systemd daemon: {result.stderr}")
            
            logger.info("✅ EDR agent service uninstalled successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Service uninstallation failed: {e}")
            return False
    
    def start_service(self) -> bool:
        """Start EDR agent service"""
        try:
            if not self.check_root_privileges():
                logger.error("❌ Root privileges required to start service")
                return False
            
            logger.info("🚀 Starting EDR agent service...")
            
            result = subprocess.run(
                ['systemctl', 'start', self.service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to start service: {result.stderr}")
                return False
            
            logger.info("✅ EDR agent service started successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Service start failed: {e}")
            return False
    
    def stop_service(self) -> bool:
        """Stop EDR agent service"""
        try:
            if not self.check_root_privileges():
                logger.error("❌ Root privileges required to stop service")
                return False
            
            logger.info("🛑 Stopping EDR agent service...")
            
            result = subprocess.run(
                ['systemctl', 'stop', self.service_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to stop service: {result.stderr}")
                return False
            
            logger.info("✅ EDR agent service stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Service stop failed: {e}")
            return False
    
    def restart_service(self) -> bool:
        """Restart EDR agent service"""
        try:
            if not self.check_root_privileges():
                logger.error("❌ Root privileges required to restart service")
                return False
            
            logger.info("🔄 Restarting EDR agent service...")
            
            result = subprocess.run(
                ['systemctl', 'restart', self.service_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to restart service: {result.stderr}")
                return False
            
            logger.info("✅ EDR agent service restarted successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Service restart failed: {e}")
            return False
    
    def reload_service(self) -> bool:
        """Reload EDR agent service configuration"""
        try:
            if not self.check_root_privileges():
                logger.error("❌ Root privileges required to reload service")
                return False
            
            logger.info("🔄 Reloading EDR agent service...")
            
            result = subprocess.run(
                ['systemctl', 'reload', self.service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Failed to reload service: {result.stderr}")
                return False
            
            logger.info("✅ EDR agent service reloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Service reload failed: {e}")
            return False
    
    def is_service_installed(self) -> bool:
        """Check if service is installed"""
        return os.path.exists(self.service_file)
    
    def is_service_enabled(self) -> bool:
        """Check if service is enabled"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-enabled', self.service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0 and result.stdout.strip() == 'enabled'
        except Exception as e:
            logger.error(f"Failed to check if service is enabled: {e}")
            return False
    
    def is_service_running(self) -> bool:
        """Check if service is running"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', self.service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0 and result.stdout.strip() == 'active'
        except Exception as e:
            logger.error(f"Failed to check if service is running: {e}")
            return False
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get detailed service status"""
        try:
            status = {
                'installed': self.is_service_installed(),
                'enabled': self.is_service_enabled(),
                'running': self.is_service_running(),
                'active_state': 'unknown',
                'load_state': 'unknown',
                'sub_state': 'unknown',
                'pid': None,
                'memory_usage': None,
                'cpu_usage': None
            }
            
            if status['installed']:
                # Get detailed status
                result = subprocess.run(
                    ['systemctl', 'show', self.service_name, '--property=ActiveState,LoadState,SubState,MainPID'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if '=' in line:
                            key, value = line.split('=', 1)
                            if key == 'ActiveState':
                                status['active_state'] = value
                            elif key == 'LoadState':
                                status['load_state'] = value
                            elif key == 'SubState':
                                status['sub_state'] = value
                            elif key == 'MainPID':
                                status['pid'] = int(value) if value.isdigit() else None
                
                # Get resource usage if running
                if status['running'] and status['pid']:
                    try:
                        import psutil
                        process = psutil.Process(status['pid'])
                        status['memory_usage'] = process.memory_info().rss
                        status['cpu_usage'] = process.cpu_percent()
                    except:
                        pass
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get service status: {e}")
            return {'error': str(e)}
    
    def get_service_logs(self, lines: int = 50) -> List[str]:
        """Get service logs"""
        try:
            result = subprocess.run(
                ['journalctl', '-u', self.service_name, '-n', str(lines), '--no-pager'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
            else:
                logger.error(f"Failed to get service logs: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get service logs: {e}")
            return []
    
    def get_service_metrics(self) -> Dict[str, Any]:
        """Get service performance metrics"""
        try:
            metrics = {
                'uptime': None,
                'memory_usage': None,
                'cpu_usage': None,
                'restart_count': 0,
                'last_restart': None
            }
            
            if self.is_service_running():
                status = self.get_service_status()
                if status.get('pid'):
                    try:
                        import psutil
                        import time
                        
                        process = psutil.Process(status['pid'])
                        
                        # Get uptime
                        metrics['uptime'] = time.time() - process.create_time()
                        
                        # Get memory usage
                        memory_info = process.memory_info()
                        metrics['memory_usage'] = {
                            'rss': memory_info.rss,
                            'vms': memory_info.vms,
                            'percent': process.memory_percent()
                        }
                        
                        # Get CPU usage
                        metrics['cpu_usage'] = process.cpu_percent()
                        
                    except Exception as e:
                        logger.debug(f"Could not get process metrics: {e}")
                
                # Get restart information
                try:
                    result = subprocess.run(
                        ['systemctl', 'show', self.service_name, '--property=NRestarts,LastTriggerUSec'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            if '=' in line:
                                key, value = line.split('=', 1)
                                if key == 'NRestarts':
                                    metrics['restart_count'] = int(value) if value.isdigit() else 0
                                elif key == 'LastTriggerUSec':
                                    metrics['last_restart'] = value
                                    
                except Exception as e:
                    logger.debug(f"Could not get restart metrics: {e}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get service metrics: {e}")
            return {'error': str(e)}
    
    def validate_service_configuration(self) -> Dict[str, Any]:
        """Validate service configuration"""
        try:
            validation = {
                'valid': True,
                'errors': [],
                'warnings': [],
                'checks': {}
            }
            
            # Check if service file exists
            if not os.path.exists(self.service_file):
                validation['valid'] = False
                validation['errors'].append("Service file does not exist")
            else:
                validation['checks']['service_file'] = True
            
            # Check if main script exists
            if not os.path.exists(self.main_script):
                validation['valid'] = False
                validation['errors'].append(f"Main script not found: {self.main_script}")
            else:
                validation['checks']['main_script'] = True
            
            # Check if Python executable exists
            if not os.path.exists(self.python_executable):
                validation['valid'] = False
                validation['errors'].append(f"Python executable not found: {self.python_executable}")
            else:
                validation['checks']['python_executable'] = True
            
            # Check service file syntax
            if os.path.exists(self.service_file):
                result = subprocess.run(
                    ['systemd-analyze', 'verify', self.service_file],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    validation['valid'] = False
                    validation['errors'].append(f"Service file syntax error: {result.stderr}")
                else:
                    validation['checks']['syntax'] = True
            
            # Check permissions
            if os.path.exists(self.service_file):
                stat_info = os.stat(self.service_file)
                if stat_info.st_uid != 0:
                    validation['warnings'].append("Service file not owned by root")
                if oct(stat_info.st_mode)[-3:] != '644':
                    validation['warnings'].append("Service file has incorrect permissions")
                else:
                    validation['checks']['permissions'] = True
            
            return validation
            
        except Exception as e:
            logger.error(f"Failed to validate service configuration: {e}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def backup_service_file(self) -> bool:
        """Create backup of service file"""
        try:
            if os.path.exists(self.service_file):
                backup_file = f"{self.service_file}.backup"
                shutil.copy2(self.service_file, backup_file)
                logger.info(f"✅ Service file backed up to: {backup_file}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to backup service file: {e}")
            return False
    
    def restore_service_file(self) -> bool:
        """Restore service file from backup"""
        try:
            backup_file = f"{self.service_file}.backup"
            if os.path.exists(backup_file):
                shutil.copy2(backup_file, self.service_file)
                logger.info(f"✅ Service file restored from: {backup_file}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to restore service file: {e}")
            return False
