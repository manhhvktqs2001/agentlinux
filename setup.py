#!/usr/bin/env python3
"""
Linux EDR Agent Setup
Setup script for Linux EDR Agent installation and packaging
"""

import os
import sys
import subprocess
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
from pathlib import Path

# Read the README file
def read_readme():
    readme_path = Path(__file__).parent / "README.md"
    if readme_path.exists():
        return readme_path.read_text(encoding='utf-8')
    return "Linux EDR Agent - Endpoint Detection and Response Agent for Linux systems"

# Read requirements
def read_requirements():
    requirements_path = Path(__file__).parent / "requirements.txt"
    if requirements_path.exists():
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

class PostInstallCommand(install):
    """Post-installation commands"""
    
    def run(self):
        install.run(self)
        self._post_install()
    
    def _post_install(self):
        """Run post-installation tasks"""
        print("🔧 Running post-installation tasks...")
        
        # Create necessary directories
        self._create_directories()
        
        # Set up logging
        self._setup_logging()
        
        # Create configuration files
        self._create_config_files()
        
        # Set up systemd service (if running as root)
        if os.geteuid() == 0:
            self._setup_systemd_service()
        
        print("✅ Post-installation tasks completed")

class PostDevelopCommand(develop):
    """Post-development installation commands"""
    
    def run(self):
        develop.run(self)
        self._post_develop()
    
    def _post_develop(self):
        """Run post-development installation tasks"""
        print("🔧 Running post-development installation tasks...")
        
        # Create necessary directories
        self._create_directories()
        
        # Set up logging
        self._setup_logging()
        
        # Create configuration files
        self._create_config_files()
        
        print("✅ Post-development installation tasks completed")

def _create_directories():
    """Create necessary directories"""
    directories = [
        '/var/log/edr-agent',
        '/var/cache/edr-agent',
        '/etc/edr-agent',
        '/var/lib/edr-agent',
        '/tmp/edr-agent'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"📁 Created directory: {directory}")
        except PermissionError:
            print(f"⚠️ Could not create directory (permission denied): {directory}")
        except Exception as e:
            print(f"❌ Error creating directory {directory}: {e}")

def _setup_logging():
    """Set up logging configuration"""
    log_dir = '/var/log/edr-agent'
    try:
        if os.path.exists(log_dir):
            # Create log files with proper permissions
            log_files = [
                'edr-agent.log',
                'edr-agent-error.log',
                'edr-agent-debug.log'
            ]
            
            for log_file in log_files:
                log_path = os.path.join(log_dir, log_file)
                if not os.path.exists(log_path):
                    with open(log_path, 'w') as f:
                        pass
                    os.chmod(log_path, 0o644)
                    print(f"📝 Created log file: {log_path}")
    except Exception as e:
        print(f"❌ Error setting up logging: {e}")

def _create_config_files():
    """Create default configuration files"""
    config_dir = '/etc/edr-agent'
    try:
        if os.path.exists(config_dir):
            # Create default configuration files
            config_files = {
                'agent_config.yaml': _get_default_agent_config(),
                'detection_rules.yaml': _get_default_detection_rules(),
                'logging_config.yaml': _get_default_logging_config(),
                'server_endpoints.yaml': _get_default_server_endpoints()
            }
            
            for filename, content in config_files.items():
                config_path = os.path.join(config_dir, filename)
                if not os.path.exists(config_path):
                    with open(config_path, 'w') as f:
                        f.write(content)
                    os.chmod(config_path, 0o644)
                    print(f"📄 Created config file: {config_path}")
    except Exception as e:
        print(f"❌ Error creating config files: {e}")

def _setup_systemd_service():
    """Set up systemd service"""
    try:
        # Check if systemd is available
        result = subprocess.run(['systemctl', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("⚙️ Systemd detected - service setup available")
            print("   Run 'sudo python3 setup.py install' to install as service")
        else:
            print("⚠️ Systemd not available - service setup skipped")
    except Exception as e:
        print(f"❌ Error checking systemd: {e}")

def _get_default_agent_config():
    """Get default agent configuration"""
    return """# EDR Agent Configuration
# Linux EDR Agent default configuration

agent:
  name: "linux-edr-agent"
  version: "1.0.0"
  hostname: ""
  ip_address: ""
  operating_system: "Linux"
  architecture: ""
  
  # Agent behavior
  polling_interval: 30
  heartbeat_interval: 60
  retry_attempts: 3
  retry_delay: 5
  
  # Security settings
  encryption_enabled: true
  certificate_validation: true
  secure_communication: true

collection:
  # Data collection settings
  collect_processes: true
  collect_files: true
  collect_network: true
  collect_system: true
  collect_authentication: true
  collect_containers: true
  
  # Collection intervals (seconds)
  process_interval: 30
  file_interval: 60
  network_interval: 30
  system_interval: 60
  authentication_interval: 15
  container_interval: 60

detection:
  # Detection engine settings
  rules_enabled: true
  threat_intel_enabled: true
  local_scanning: true
  
  # Scan intervals
  full_scan_interval: 3600  # 1 hour
  quick_scan_interval: 300  # 5 minutes
  
  # Thresholds
  suspicious_process_threshold: 5
  failed_login_threshold: 10
  network_anomaly_threshold: 0.8

communication:
  # Server communication settings
  server_url: "http://localhost:5000"
  api_version: "v1"
  timeout: 30
  max_retries: 3
  
  # Authentication
  api_key: ""
  certificate_path: ""
  
  # Proxy settings (if needed)
  proxy_enabled: false
  proxy_url: ""
  proxy_username: ""
  proxy_password: ""

logging:
  # Logging configuration
  level: "INFO"
  file_enabled: true
  console_enabled: true
  syslog_enabled: true
  
  # Log files
  log_file: "/var/log/edr-agent/edr-agent.log"
  error_file: "/var/log/edr-agent/edr-agent-error.log"
  debug_file: "/var/log/edr-agent/edr-agent-debug.log"
  
  # Log rotation
  max_size: "10MB"
  backup_count: 5

performance:
  # Performance monitoring
  enabled: true
  metrics_interval: 60
  
  # Resource limits
  max_memory_usage: "512MB"
  max_cpu_usage: 80
  max_disk_usage: "1GB"

security:
  # Security settings
  anti_tamper_enabled: true
  integrity_checking: true
  process_protection: true
  
  # File monitoring
  critical_files:
    - "/etc/passwd"
    - "/etc/shadow"
    - "/etc/sudoers"
    - "/etc/ssh/sshd_config"
  
  # Process monitoring
  critical_processes:
    - "sshd"
    - "systemd"
    - "cron"
    - "auditd"

notifications:
  # Notification settings
  email_enabled: false
  email_server: ""
  email_port: 587
  email_username: ""
  email_password: ""
  email_recipients: []
  
  # Slack notifications
  slack_enabled: false
  slack_webhook: ""
  slack_channel: ""
  
  # Webhook notifications
  webhook_enabled: false
  webhook_url: ""
"""

def _get_default_detection_rules():
    """Get default detection rules"""
    return """# EDR Detection Rules
# Default detection rules for Linux EDR Agent

rules:
  # Process-based rules
  suspicious_processes:
    - name: "Suspicious Process Creation"
      description: "Detect creation of suspicious processes"
      type: "process_creation"
      conditions:
        - field: "process_name"
          operator: "in"
          value: ["nc", "netcat", "wget", "curl", "bash", "sh"]
        - field: "parent_process"
          operator: "not_in"
          value: ["sshd", "bash", "sh", "systemd"]
      severity: "MEDIUM"
      action: "alert"
      
    - name: "Privilege Escalation"
      description: "Detect privilege escalation attempts"
      type: "process_creation"
      conditions:
        - field: "process_name"
          operator: "in"
          value: ["sudo", "su", "doas"]
        - field: "user"
          operator: "not_in"
          value: ["root", "admin"]
      severity: "HIGH"
      action: "alert"
  
  # File-based rules
  suspicious_files:
    - name: "Suspicious File Creation"
      description: "Detect creation of suspicious files"
      type: "file_creation"
      conditions:
        - field: "file_extension"
          operator: "in"
          value: [".exe", ".bat", ".cmd", ".scr", ".pif"]
        - field: "file_path"
          operator: "contains"
          value: "/tmp"
      severity: "HIGH"
      action: "alert"
      
    - name: "System File Modification"
      description: "Detect modification of critical system files"
      type: "file_modification"
      conditions:
        - field: "file_path"
          operator: "in"
          value: ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
      severity: "CRITICAL"
      action: "block"
  
  # Network-based rules
  suspicious_network:
    - name: "Suspicious Network Connection"
      description: "Detect suspicious network connections"
      type: "network_connection"
      conditions:
        - field: "remote_port"
          operator: "in"
          value: [22, 23, 3389, 5900]
        - field: "local_user"
          operator: "not_in"
          value: ["root", "admin"]
      severity: "MEDIUM"
      action: "alert"
      
    - name: "Data Exfiltration"
      description: "Detect potential data exfiltration"
      type: "network_connection"
      conditions:
        - field: "bytes_sent"
          operator: "greater_than"
          value: 10485760  # 10MB
        - field: "remote_ip"
          operator: "not_in"
          value: ["127.0.0.1", "::1"]
      severity: "HIGH"
      action: "alert"
  
  # Authentication-based rules
  suspicious_authentication:
    - name: "Failed Login Attempts"
      description: "Detect multiple failed login attempts"
      type: "authentication_failure"
      conditions:
        - field: "failure_count"
          operator: "greater_than"
          value: 5
        - field: "time_window"
          operator: "less_than"
          value: 300  # 5 minutes
      severity: "MEDIUM"
      action: "alert"
      
    - name: "Brute Force Attack"
      description: "Detect brute force attack patterns"
      type: "authentication_failure"
      conditions:
        - field: "failure_count"
          operator: "greater_than"
          value: 10
        - field: "time_window"
          operator: "less_than"
          value: 600  # 10 minutes
      severity: "HIGH"
      action: "block"
  
  # System-based rules
  suspicious_system:
    - name: "System Service Failure"
      description: "Detect critical system service failures"
      type: "service_failure"
      conditions:
        - field: "service_name"
          operator: "in"
          value: ["sshd", "systemd", "auditd"]
      severity: "HIGH"
      action: "alert"
      
    - name: "High System Load"
      description: "Detect unusually high system load"
      type: "system_performance"
      conditions:
        - field: "load_average"
          operator: "greater_than"
          value: 10.0
        - field: "duration"
          operator: "greater_than"
          value: 300  # 5 minutes
      severity: "MEDIUM"
      action: "alert"

# Rule actions
actions:
  alert:
    description: "Generate alert notification"
    type: "notification"
    
  block:
    description: "Block the activity"
    type: "prevention"
    
  quarantine:
    description: "Quarantine the file/process"
    type: "isolation"
    
  log:
    description: "Log the activity"
    type: "logging"

# Rule priorities
priorities:
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 3
  LOW: 4
  INFO: 5
"""

def _get_default_logging_config():
    """Get default logging configuration"""
    return """# EDR Agent Logging Configuration
# Logging configuration for Linux EDR Agent

version: 1
disable_existing_loggers: false

formatters:
  standard:
    format: '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    datefmt: '%Y-%m-%d %H:%M:%S'
  
  detailed:
    format: '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
    datefmt: '%Y-%m-%d %H:%M:%S'
  
  json:
    format: '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'
    datefmt: '%Y-%m-%d %H:%M:%S'

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: standard
    stream: ext://sys.stdout
  
  file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: detailed
    filename: /var/log/edr-agent/edr-agent.log
    maxBytes: 10485760  # 10MB
    backupCount: 5
    encoding: utf8
  
  error_file:
    class: logging.handlers.RotatingFileHandler
    level: ERROR
    formatter: detailed
    filename: /var/log/edr-agent/edr-agent-error.log
    maxBytes: 10485760  # 10MB
    backupCount: 5
    encoding: utf8
  
  debug_file:
    class: logging.handlers.RotatingFileHandler
    level: DEBUG
    formatter: detailed
    filename: /var/log/edr-agent/edr-agent-debug.log
    maxBytes: 10485760  # 10MB
    backupCount: 5
    encoding: utf8
  
  syslog:
    class: logging.handlers.SysLogHandler
    level: WARNING
    formatter: standard
    address: /dev/log
    facility: local0

loggers:
  edr_agent:
    level: INFO
    handlers: [console, file, error_file, syslog]
    propagate: false
  
  edr_agent.collectors:
    level: INFO
    handlers: [file, error_file]
    propagate: false
  
  edr_agent.detection:
    level: INFO
    handlers: [file, error_file, syslog]
    propagate: false
  
  edr_agent.communication:
    level: INFO
    handlers: [file, error_file]
    propagate: false
  
  edr_agent.security:
    level: INFO
    handlers: [file, error_file, syslog]
    propagate: false

root:
  level: WARNING
  handlers: [console, file, error_file]
"""

def _get_default_server_endpoints():
    """Get default server endpoints configuration"""
    return """# EDR Server Endpoints Configuration
# Server communication endpoints for Linux EDR Agent

server:
  base_url: "http://localhost:5000"
  api_version: "v1"
  timeout: 30
  max_retries: 3
  
  # Authentication
  api_key: ""
  certificate_path: ""
  verify_ssl: true

endpoints:
  # Agent management endpoints
  agent:
    register: "/api/v1/agents/register"
    heartbeat: "/api/v1/agents/heartbeat"
    status: "/api/v1/agents/status"
    update: "/api/v1/agents/update"
    unregister: "/api/v1/agents/unregister"
  
  # Event submission endpoints
  events:
    submit: "/api/v1/events/submit"
    batch_submit: "/api/v1/events/batch-submit"
    status: "/api/v1/events/status"
  
  # Alert endpoints
  alerts:
    submit: "/api/v1/alerts/submit"
    batch_submit: "/api/v1/alerts/batch-submit"
    status: "/api/v1/alerts/status"
  
  # Threat intelligence endpoints
  threats:
    check: "/api/v1/threats/check"
    report: "/api/v1/threats/report"
    status: "/api/v1/threats/status"
  
  # Detection engine endpoints
  detection:
    rules: "/api/v1/detection/rules"
    scan: "/api/v1/detection/scan"
    status: "/api/v1/detection/status"
  
  # Configuration endpoints
  config:
    get: "/api/v1/config/get"
    update: "/api/v1/config/update"
    validate: "/api/v1/config/validate"
  
  # Health check endpoints
  health:
    check: "/api/v1/health/check"
    status: "/api/v1/health/status"

# Proxy configuration (if needed)
proxy:
  enabled: false
  http: ""
  https: ""
  username: ""
  password: ""

# SSL/TLS configuration
ssl:
  verify: true
  cert_file: ""
  key_file: ""
  ca_file: ""
  check_hostname: true

# Rate limiting
rate_limit:
  enabled: true
  requests_per_minute: 60
  burst_size: 10

# Retry configuration
retry:
  max_attempts: 3
  backoff_factor: 2
  max_delay: 60
  retry_on_status_codes: [500, 502, 503, 504]
"""

# Setup configuration
setup(
    name="linux-edr-agent",
    version="1.0.0",
    description="Linux EDR Agent - Endpoint Detection and Response Agent for Linux systems",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="EDR Project Team",
    author_email="team@edr-project.com",
    url="https://github.com/edr-project/linux-agent",
    project_urls={
        "Bug Tracker": "https://github.com/edr-project/linux-agent/issues",
        "Documentation": "https://edr-project.github.io/linux-agent/",
        "Source Code": "https://github.com/edr-project/linux-agent",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    keywords="edr, endpoint, detection, response, security, monitoring, linux",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
        "ml": [
            "numpy>=1.21.0",
            "scikit-learn>=1.1.0",
            "pandas>=1.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "edr-agent=agent.main:main",
            "edr-agent-service=agent.service.systemd_service:main",
        ],
    },
    cmdclass={
        "install": PostInstallCommand,
        "develop": PostDevelopCommand,
    },
    include_package_data=True,
    package_data={
        "agent": [
            "config/*.yaml",
            "config/*.yml",
            "config/*.json",
            "schemas/*.json",
            "detection/rules/*.yaml",
            "detection/rules/*.yml",
        ],
    },
    data_files=[
        ("/etc/edr-agent", [
            "config/agent_config.yaml",
            "config/detection_rules.yaml",
            "config/logging_config.yaml",
            "config/server_endpoints.yaml",
        ]),
        ("/var/log/edr-agent", []),
        ("/var/cache/edr-agent", []),
        ("/var/lib/edr-agent", []),
        ("/tmp/edr-agent", []),
    ],
    zip_safe=False,
    platforms=["Linux"],
    license="MIT",
)
