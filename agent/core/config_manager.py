# agent/core/config_manager.py - Linux Configuration Manager
"""
Linux Configuration Manager - Handle agent configuration for Linux systems
Optimized for Linux environments with platform-specific settings
"""

import yaml
import json
import logging
import os
import pwd
import grp
from pathlib import Path
from typing import Dict, Any, Optional
import uuid

class LinuxConfigManager:
    """Manage Linux agent configuration with platform-specific features"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config: Dict[str, Any] = {}
        self.config_file = None
        
        # Linux-specific paths
        self.system_config_paths = [
            '/etc/edr-agent/agent_config.yaml',
            '/etc/edr-agent/config.yaml',
            '/opt/edr-agent/config/agent_config.yaml'
        ]
        
        self.user_config_paths = [
            Path.home() / '.edr-agent' / 'config.yaml',
            Path.home() / '.config' / 'edr-agent' / 'config.yaml'
        ]
        
        # Default configuration optimized for Linux
        self.default_config = self._get_linux_default_config()
        
        # Linux system information
        self.linux_info = self._get_linux_system_info()
        
        self.logger.info("🐧 Linux Configuration Manager initialized")
    
    def _get_linux_system_info(self) -> Dict[str, Any]:
        """Get Linux system information for configuration"""
        try:
            info = {
                'platform': 'linux',
                'hostname': os.uname().nodename,
                'kernel': os.uname().release,
                'architecture': os.uname().machine,
                'current_user': pwd.getpwuid(os.getuid()).pw_name,
                'effective_user': pwd.getpwuid(os.geteuid()).pw_name,
                'is_root': os.geteuid() == 0,
                'home_directory': str(Path.home()),
                'working_directory': os.getcwd()
            }
            
            # Get distribution information
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('NAME='):
                            info['distribution'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('VERSION='):
                            info['version'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('ID='):
                            info['distribution_id'] = line.split('=')[1].strip().strip('"')
            except:
                info['distribution'] = 'Unknown'
                info['version'] = 'Unknown'
            
            # Get group information
            try:
                groups = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]
                info['groups'] = groups
            except:
                info['groups'] = []
            
            return info
            
        except Exception as e:
            self.logger.error(f"❌ Error getting Linux system info: {e}")
            return {'platform': 'linux', 'error': str(e)}
    
    async def load_config(self, config_path: Optional[str] = None):
        """Load configuration from file with Linux-specific logic"""
        try:
            self.logger.info("📋 Loading Linux agent configuration...")
            
            # Determine config file path
            config_file_found = False
            
            if config_path:
                # Use provided path
                self.config_file = Path(config_path)
                if self.config_file.exists():
                    config_file_found = True
            else:
                # Search for config files in Linux standard locations
                search_paths = []
                
                # Add system-wide config paths (if root)
                if self.linux_info.get('is_root'):
                    search_paths.extend(self.system_config_paths)
                
                # Add user config paths
                search_paths.extend(self.user_config_paths)
                
                # Add local paths
                current_dir = Path(__file__).parent.parent.parent
                search_paths.extend([
                    current_dir / 'config' / 'agent_config.yaml',
                    current_dir / 'agent_config.yaml',
                    Path('agent_config.yaml'),
                    Path('config') / 'agent_config.yaml'
                ])
                
                for path in search_paths:
                    if Path(path).exists() and os.access(path, os.R_OK):
                        self.config_file = Path(path)
                        config_file_found = True
                        break
            
            # Load config from file or use defaults
            if config_file_found and self.config_file:
                self.config = self._load_from_file(self.config_file)
                self.logger.info(f"✅ Linux configuration loaded from: {self.config_file}")
            else:
                self.config = self.default_config.copy()
                self.logger.info("✅ Using Linux default configuration")
            
            # Apply Linux-specific configuration adjustments
            self._apply_linux_config_adjustments()
            
            # Validate configuration
            self._validate_linux_config()
            
            self.logger.info("✅ Linux configuration loaded successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load Linux configuration: {e}")
            raise
    
    def _load_from_file(self, file_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML or JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.suffix.lower() in ['.yaml', '.yml']:
                    config = yaml.safe_load(f) or {}
                elif file_path.suffix.lower() == '.json':
                    config = json.load(f) or {}
                else:
                    # Try YAML first, then JSON
                    content = f.read()
                    try:
                        config = yaml.safe_load(content) or {}
                    except:
                        config = json.loads(content) or {}
                
                self.logger.debug(f"Loaded {len(config)} configuration sections from {file_path}")
                return config
                        
        except Exception as e:
            self.logger.error(f"❌ Failed to load config file {file_path}: {e}")
            return {}
    
    def _get_linux_default_config(self) -> Dict[str, Any]:
        """Get default Linux agent configuration"""
        return {
            'agent': {
                'name': 'EDR-Agent-Linux',
                'version': '2.1.0-Linux',
                'platform': 'linux',
                'heartbeat_interval': 30,
                'event_batch_size': 100,
                'event_queue_size': 2000,
                'max_memory_usage': 512,  # MB
                'debug_mode': False,
                'requires_root': True
            },
            'server': {
                'host': '192.168.20.85',
                'port': 5000,
                'auth_token': 'edr_agent_auth_2024',
                'timeout': 30,
                'max_retries': 3,
                'retry_delay': 5,
                'ssl_enabled': False,
                'ssl_verify': True
            },
            'collection': {
                'enabled': True,
                'collect_processes': True,
                'collect_files': True,
                'collect_network': True,
                'collect_registry': False,  # Not applicable to Linux
                'collect_authentication': True,
                'collect_system_events': True,
                'collect_containers': True,  # Linux-specific
                'collect_audit_logs': True,  # Linux-specific
                'real_time_monitoring': True,
                'polling_interval': 3,
                'max_events_per_interval': 1000
            },
            'linux_specific': {
                'monitor_proc_filesystem': True,
                'monitor_sys_filesystem': True,
                'use_inotify': True,
                'monitor_systemd': True,
                'monitor_audit_daemon': True,
                'monitor_syslog': True,
                'monitor_docker': True,
                'monitor_ssh_connections': True,
                'monitor_cron_jobs': True,
                'monitor_user_sessions': True,
                'paths_to_monitor': [
                    '/etc',
                    '/usr/bin',
                    '/usr/sbin',
                    '/bin',
                    '/sbin',
                    '/home',
                    '/tmp',
                    '/var/tmp',
                    '/opt'
                ],
                'exclude_paths': [
                    '/proc',
                    '/sys',
                    '/dev',
                    '/run',
                    '/tmp/.X11-unix'
                ],
                'sensitive_files': [
                    '/etc/passwd',
                    '/etc/shadow',
                    '/etc/sudoers',
                    '/etc/ssh/sshd_config',
                    '/etc/hosts',
                    '/etc/crontab'
                ]
            },
            'detection': {
                'enabled': True,
                'local_rules_enabled': True,
                'behavior_analysis': True,
                'threat_cache_enabled': True,
                'cache_size': 10000,
                'suspicious_threshold': 70,
                'linux_specific_rules': True
            },
            'logging': {
                'level': 'INFO',
                'file_enabled': True,
                'console_enabled': True,
                'syslog_enabled': True,  # Linux-specific
                'max_file_size': '10MB',
                'backup_count': 5,
                'log_directory': '/var/log/edr-agent' if os.geteuid() == 0 else str(Path.home() / '.edr-agent' / 'logs')
            },
            'security': {
                'anti_tamper_enabled': True,
                'integrity_check_enabled': True,
                'encryption_enabled': False,
                'secure_communication': True,
                'file_permissions_check': True,  # Linux-specific
                'selinux_aware': True,  # Linux-specific
                'apparmor_aware': True  # Linux-specific
            },
            'performance': {
                'max_cpu_usage': 25,
                'max_memory_usage': 512,
                'monitoring_enabled': True,
                'auto_throttle': True,
                'batch_processing': True,
                'use_cgroups': True,  # Linux-specific
                'nice_level': 10  # Linux-specific
            },
            'filters': {
                'exclude_system_processes': True,
                'exclude_kernel_threads': True,  # Linux-specific
                'exclude_agent_activity': True,
                'exclude_process_names': [
                    'kthreadd',
                    'ksoftirqd',
                    'migration',
                    'rcu_',
                    'watchdog'
                ],
                'exclude_process_paths': [
                    '/lib/systemd',
                    '/usr/lib/systemd'
                ],
                'exclude_file_extensions': [
                    '.tmp',
                    '.log',
                    '.cache',
                    '.pid',
                    '.lock'
                ],
                'exclude_file_paths': [
                    '/tmp',
                    '/var/tmp',
                    '/var/log',
                    '/var/cache'
                ],
                'exclude_network_interfaces': [
                    'lo'
                ],
                'max_file_size_mb': 100,
                'max_command_line_length': 2048
            },
            'systemd': {
                'service_name': 'edr-agent',
                'service_description': 'EDR Security Agent for Linux',
                'service_user': 'root',
                'service_group': 'root',
                'restart_policy': 'always',
                'start_limit_interval': 300,
                'start_limit_burst': 5
            }
        }
    
    def _apply_linux_config_adjustments(self):
        """Apply Linux-specific configuration adjustments"""
        try:
            # Adjust paths based on user privileges
            if not self.linux_info.get('is_root'):
                # Non-root adjustments
                self.config.setdefault('logging', {})['log_directory'] = str(Path.home() / '.edr-agent' / 'logs')
                
                # Reduce monitoring scope for non-root
                self.config.setdefault('linux_specific', {})['monitor_audit_daemon'] = False
                self.config.setdefault('performance', {})['max_memory_usage'] = 256
                
                self.logger.warning("⚠️ Running as non-root user - some monitoring features may be limited")
            
            # Adjust based on distribution
            distribution = self.linux_info.get('distribution', '').lower()
            if 'ubuntu' in distribution or 'debian' in distribution:
                # Debian-based adjustments
                self.config.setdefault('linux_specific', {})['package_manager'] = 'apt'
                self.config.setdefault('linux_specific', {})['service_manager'] = 'systemd'
            elif 'centos' in distribution or 'rhel' in distribution or 'fedora' in distribution:
                # RedHat-based adjustments
                self.config.setdefault('linux_specific', {})['package_manager'] = 'yum'
                self.config.setdefault('linux_specific', {})['service_manager'] = 'systemd'
            elif 'arch' in distribution:
                # Arch-based adjustments
                self.config.setdefault('linux_specific', {})['package_manager'] = 'pacman'
                self.config.setdefault('linux_specific', {})['service_manager'] = 'systemd'
            
            # Set hostname
            self.config.setdefault('agent', {})['hostname'] = self.linux_info.get('hostname', 'unknown')
            
            # Ensure directories exist
            self._ensure_linux_directories()
            
        except Exception as e:
            self.logger.error(f"❌ Error applying Linux config adjustments: {e}")
    
    def _ensure_linux_directories(self):
        """Ensure required Linux directories exist"""
        try:
            # Log directory
            log_dir = Path(self.config.get('logging', {}).get('log_directory', '/tmp/edr-agent'))
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Config directory for user configs
            if not self.linux_info.get('is_root'):
                config_dir = Path.home() / '.edr-agent'
                config_dir.mkdir(parents=True, exist_ok=True)
            
            # Runtime directory
            if self.linux_info.get('is_root'):
                runtime_dir = Path('/var/run/edr-agent')
                runtime_dir.mkdir(parents=True, exist_ok=True)
            
        except Exception as e:
            self.logger.error(f"❌ Error creating Linux directories: {e}")
    
    def _validate_linux_config(self):
        """Validate Linux-specific configuration"""
        try:
            # Check required sections
            required_sections = ['agent', 'server', 'collection']
            for section in required_sections:
                if section not in self.config:
                    raise ValueError(f"Missing required configuration section: {section}")
            
            # Validate agent configuration
            agent_config = self.config.get('agent', {})
            if not agent_config.get('agent_id'):
                self.config['agent']['agent_id'] = str(uuid.uuid4())
            
            # Set platform
            self.config['agent']['platform'] = 'linux'
            
            # Validate server configuration
            server_config = self.config.get('server', {})
            if not server_config.get('host'):
                raise ValueError("Missing server host in configuration")
            
            # Validate collection configuration
            collection_config = self.config.get('collection', {})
            if not collection_config.get('polling_interval'):
                collection_config['polling_interval'] = 3
            
            # Validate Linux-specific paths
            linux_config = self.config.get('linux_specific', {})
            if 'paths_to_monitor' in linux_config:
                valid_paths = []
                for path in linux_config['paths_to_monitor']:
                    if os.path.exists(path) and os.access(path, os.R_OK):
                        valid_paths.append(path)
                    else:
                        self.logger.warning(f"⚠️ Cannot access monitoring path: {path}")
                linux_config['paths_to_monitor'] = valid_paths
            
            # Validate permissions
            if self.config.get('agent', {}).get('requires_root', True) and not self.linux_info.get('is_root'):
                self.logger.warning("⚠️ Agent configured to require root but not running as root")
            
            self.logger.info("✅ Linux configuration validated")
            
        except Exception as e:
            self.logger.error(f"❌ Linux configuration validation failed: {e}")
            raise
    
    def get_config(self) -> Dict[str, Any]:
        """Get complete configuration with Linux info"""
        config_with_info = self.config.copy()
        config_with_info['linux_info'] = self.linux_info
        return config_with_info
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get configuration section"""
        return self.config.get(section, {})
    
    def get_linux_specific_config(self) -> Dict[str, Any]:
        """Get Linux-specific configuration section"""
        return self.config.get('linux_specific', {})
    
    def get_value(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        try:
            keys = key_path.split('.')
            value = self.config
            
            for key in keys:
                value = value[key]
            
            return value
            
        except (KeyError, TypeError):
            return default
    
    def set_value(self, key_path: str, value: Any):
        """Set configuration value using dot notation"""
        try:
            keys = key_path.split('.')
            config_section = self.config
            
            for key in keys[:-1]:
                if key not in config_section:
                    config_section[key] = {}
                config_section = config_section[key]
            
            config_section[keys[-1]] = value
            self.logger.debug(f"Linux config updated: {key_path} = {value}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to set Linux config {key_path}: {e}")
    
    def update_from_server(self, server_config: Dict[str, Any]):
        """Update configuration from server response"""
        try:
            # Update heartbeat interval
            if 'heartbeat_interval' in server_config:
                self.set_value('agent.heartbeat_interval', server_config['heartbeat_interval'])
            
            # Update monitoring settings
            if 'monitoring_enabled' in server_config:
                self.set_value('collection.enabled', server_config['monitoring_enabled'])
            
            # Update event batch size
            if 'event_batch_size' in server_config:
                self.set_value('agent.event_batch_size', server_config['event_batch_size'])
            
            # Update collection settings
            if 'collection_settings' in server_config:
                collection_settings = server_config['collection_settings']
                for key, value in collection_settings.items():
                    self.set_value(f'collection.{key}', value)
            
            # Update detection settings
            if 'detection_settings' in server_config:
                detection_settings = server_config['detection_settings']
                for key, value in detection_settings.items():
                    self.set_value(f'detection.{key}', value)
            
            self.logger.info("✅ Linux configuration updated from server")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to update Linux config from server: {e}")
    
    def save_config(self, file_path: Optional[str] = None):
        """Save current configuration to file"""
        try:
            if file_path:
                output_file = Path(file_path)
            elif self.config_file:
                output_file = self.config_file
            else:
                # Choose appropriate location based on privileges
                if self.linux_info.get('is_root'):
                    output_file = Path('/etc/edr-agent/agent_config.yaml')
                else:
                    output_file = Path.home() / '.edr-agent' / 'config.yaml'
            
            # Create directory if it doesn't exist
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Remove linux_info from saved config
            save_config = self.config.copy()
            save_config.pop('linux_info', None)
            
            # Save as YAML
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(save_config, f, default_flow_style=False, indent=2)
            
            # Set appropriate permissions
            if self.linux_info.get('is_root'):
                os.chmod(output_file, 0o600)  # Root only
            else:
                os.chmod(output_file, 0o644)  # User readable
            
            self.logger.info(f"✅ Linux configuration saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to save Linux configuration: {e}")
    
    def is_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled"""
        return self.get_value(feature, False)
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.get_section('logging')
    
    def get_performance_limits(self) -> Dict[str, Any]:
        """Get performance limits"""
        return self.get_section('performance')
    
    def get_collection_settings(self) -> Dict[str, Any]:
        """Get collection settings"""
        return self.get_section('collection')
    
    def get_server_settings(self) -> Dict[str, Any]:
        """Get server connection settings"""
        return self.get_section('server')
    
    def get_linux_system_info(self) -> Dict[str, Any]:
        """Get Linux system information"""
        return self.linux_info

# Alias for compatibility
ConfigManager = LinuxConfigManager