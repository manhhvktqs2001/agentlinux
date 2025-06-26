# agent/detection/behavior_analyzer.py - Advanced Behavior Analysis
"""
Advanced Behavior Analyzer - Machine learning-based threat detection
Analyze process behavior, network patterns, and system anomalies
"""

import asyncio
import logging
import time
import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
import hashlib

@dataclass
class BehaviorPattern:
    """Behavior pattern data"""
    pattern_id: str
    pattern_type: str
    features: List[float]
    confidence: float
    risk_score: int
    description: str
    mitre_tactics: List[str]
    mitre_techniques: List[str]

@dataclass
class AnomalyDetection:
    """Anomaly detection result"""
    entity_id: str
    entity_type: str
    anomaly_type: str
    baseline_value: float
    current_value: float
    deviation_score: float
    timestamp: datetime

class AdvancedBehaviorAnalyzer:
    """Advanced behavior analysis with ML-based detection"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Analysis configuration
        self.enabled = True
        self.analysis_window = 300  # 5 minutes
        self.baseline_period = 3600  # 1 hour
        self.anomaly_threshold = 2.5  # Standard deviations
        self.max_events_per_analysis = 1000
        
        # Behavior tracking
        self.process_behaviors = defaultdict(list)
        self.network_behaviors = defaultdict(list)
        self.file_behaviors = defaultdict(list)
        self.user_behaviors = defaultdict(list)
        
        # Pattern detection
        self.known_patterns = {}
        self.suspicious_patterns = {}
        self.baseline_metrics = {}
        
        # Event buffers
        self.process_events = deque(maxlen=self.max_events_per_analysis)
        self.network_events = deque(maxlen=self.max_events_per_analysis)
        self.file_events = deque(maxlen=self.max_events_per_analysis)
        
        # ML Models (simplified - would use scikit-learn in production)
        self.anomaly_detectors = {}
        self.pattern_classifiers = {}
        
        # MITRE ATT&CK mapping
        self.mitre_mapping = self._initialize_mitre_mapping()
        
        # Threat indicators
        self.threat_indicators = {
            'persistence_mechanisms': [
                'cron', 'systemd', 'init.d', '.bashrc', '.profile',
                'autostart', 'systemctl enable'
            ],
            'privilege_escalation': [
                'sudo', 'su', 'setuid', 'chmod +s', 'pkexec',
                '/etc/passwd', '/etc/shadow', 'usermod'
            ],
            'defense_evasion': [
                'history -c', 'unset HISTFILE', 'rm -rf ~/.bash_history',
                'kill -9', 'pkill', 'killall', 'nohup'
            ],
            'credential_access': [
                'mimikatz', '/etc/passwd', '/etc/shadow', '.ssh/',
                'id_rsa', 'authorized_keys', 'password'
            ],
            'discovery': [
                'whoami', 'id', 'groups', 'ps aux', 'netstat',
                'ss -tuln', 'lsof', 'find', 'locate'
            ],
            'lateral_movement': [
                'ssh', 'scp', 'rsync', 'nc', 'netcat',
                'python -c', 'bash -i', '/dev/tcp'
            ],
            'collection': [
                'tar', 'zip', 'gzip', 'find', 'grep -r',
                'cat /etc/', 'mysqldump', 'pg_dump'
            ],
            'exfiltration': [
                'curl', 'wget', 'nc', 'base64', 'python -m',
                'ftp', 'scp', 'rsync'
            ]
        }
        
        self.logger.info("🧠 Advanced Behavior Analyzer initialized")
    
    def _initialize_mitre_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Initialize MITRE ATT&CK technique mapping"""
        return {
            'T1053': {
                'name': 'Scheduled Task/Job',
                'tactics': ['Persistence', 'Privilege Escalation'],
                'keywords': ['cron', 'at', 'systemd timer', 'crontab']
            },
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'tactics': ['Execution'],
                'keywords': ['bash', 'sh', 'python', 'perl', 'ruby']
            },
            'T1078': {
                'name': 'Valid Accounts',
                'tactics': ['Defense Evasion', 'Persistence', 'Privilege Escalation'],
                'keywords': ['sudo', 'su', 'login', 'ssh']
            },
            'T1083': {
                'name': 'File and Directory Discovery',
                'tactics': ['Discovery'],
                'keywords': ['find', 'locate', 'ls', 'tree', 'grep']
            },
            'T1055': {
                'name': 'Process Injection',
                'tactics': ['Defense Evasion', 'Privilege Escalation'],
                'keywords': ['gdb', 'ptrace', '/proc/', 'LD_PRELOAD']
            },
            'T1070': {
                'name': 'Indicator Removal on Host',
                'tactics': ['Defense Evasion'],
                'keywords': ['history -c', 'rm -rf', 'shred', 'wipe']
            },
            'T1105': {
                'name': 'Ingress Tool Transfer',
                'tactics': ['Command and Control'],
                'keywords': ['wget', 'curl', 'scp', 'rsync', 'base64']
            },
            'T1543': {
                'name': 'Create or Modify System Process',
                'tactics': ['Persistence', 'Privilege Escalation'],
                'keywords': ['systemctl', 'service', 'init.d', 'systemd']
            }
        }
    
    async def analyze_event(self, event_data) -> Optional[BehaviorPattern]:
        """Analyze individual event for behavioral patterns"""
        try:
            if not self.enabled:
                return None
            
            # Add event to appropriate buffer
            event_type = getattr(event_data, 'event_type', 'Unknown')
            
            if event_type == 'Process':
                self.process_events.append(event_data)
                return await self._analyze_process_behavior(event_data)
            elif event_type == 'Network':
                self.network_events.append(event_data)
                return await self._analyze_network_behavior(event_data)
            elif event_type == 'File':
                self.file_events.append(event_data)
                return await self._analyze_file_behavior(event_data)
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Event analysis failed: {e}")
            return None
    
    async def _analyze_process_behavior(self, event_data) -> Optional[BehaviorPattern]:
        """Analyze process behavior patterns"""
        try:
            process_name = getattr(event_data, 'process_name', '')
            command_line = getattr(event_data, 'command_line', '')
            user = getattr(event_data, 'process_user', '')
            
            # Check for suspicious command patterns
            suspicious_patterns = []
            
            # Check for MITRE ATT&CK techniques
            mitre_techniques = []
            mitre_tactics = []
            
            for technique_id, technique_info in self.mitre_mapping.items():
                for keyword in technique_info['keywords']:
                    if keyword.lower() in command_line.lower():
                        mitre_techniques.append(technique_id)
                        mitre_tactics.extend(technique_info['tactics'])
                        suspicious_patterns.append(f"MITRE {technique_id}: {technique_info['name']}")
            
            # Check for threat indicators
            for category, indicators in self.threat_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in command_line.lower():
                        suspicious_patterns.append(f"{category}: {indicator}")
            
            # Analyze command complexity
            complexity_score = self._calculate_command_complexity(command_line)
            
            # Check for privilege escalation patterns
            privilege_score = self._check_privilege_escalation(command_line, user)
            
            # Check for obfuscation techniques
            obfuscation_score = self._check_obfuscation(command_line)
            
            # Calculate risk score
            base_risk = 0
            if suspicious_patterns:
                base_risk = 40
            
            risk_score = min(100, base_risk + complexity_score + privilege_score + obfuscation_score)
            
            # Create behavior pattern if suspicious
            if risk_score >= 30 or suspicious_patterns:
                pattern_id = self._generate_pattern_id(event_data)
                
                return BehaviorPattern(
                    pattern_id=pattern_id,
                    pattern_type='process_behavior',
                    features=[complexity_score, privilege_score, obfuscation_score, len(suspicious_patterns)],
                    confidence=min(0.95, risk_score / 100.0),
                    risk_score=risk_score,
                    description=f"Suspicious process behavior: {', '.join(suspicious_patterns[:3])}",
                    mitre_tactics=list(set(mitre_tactics)),
                    mitre_techniques=list(set(mitre_techniques))
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Process behavior analysis failed: {e}")
            return None
    
    def _calculate_command_complexity(self, command_line: str) -> int:
        """Calculate command complexity score"""
        try:
            score = 0
            
            # Length factor
            if len(command_line) > 200:
                score += 10
            elif len(command_line) > 100:
                score += 5
            
            # Special characters
            special_chars = ['|', '&', ';', '>', '<', '`', '(', ')']
            score += min(15, sum(command_line.count(char) for char in special_chars))
            
            # Encoded content
            if any(encoding in command_line for encoding in ['base64', 'hex', 'url', '%']):
                score += 10
            
            # Multiple commands
            command_separators = [';', '&&', '||', '|']
            for sep in command_separators:
                score += command_line.count(sep) * 3
            
            return min(30, score)
            
        except Exception:
            return 0
    
    def _check_privilege_escalation(self, command_line: str, user: str) -> int:
        """Check for privilege escalation indicators"""
        try:
            score = 0
            command_lower = command_line.lower()
            
            # Sudo/su usage
            if 'sudo' in command_lower or 'su -' in command_lower:
                score += 15
            
            # SUID/SGID manipulation
            if any(term in command_lower for term in ['chmod +s', 'chmod 4755', 'setuid']):
                score += 20
            
            # System file access
            system_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
            if any(file_path in command_lower for file_path in system_files):
                score += 15
            
            # Running as root but shouldn't be
            if user == 'root' and any(cmd in command_lower for cmd in ['wget', 'curl', 'nc']):
                score += 10
            
            return min(25, score)
            
        except Exception:
            return 0
    
    def _check_obfuscation(self, command_line: str) -> int:
        """Check for command obfuscation techniques"""
        try:
            score = 0
            command_lower = command_line.lower()
            
            # Base64 encoding
            if 'base64' in command_lower or len([c for c in command_line if c.isalnum()]) / len(command_line) > 0.8:
                score += 15
            
            # Hex encoding
            if '\\x' in command_line or any(f'0x{i}' in command_line for i in range(10)):
                score += 10
            
            # Unicode escaping
            if '\\u' in command_line:
                score += 10
            
            # Environment variable obfuscation
            if command_line.count(')') > 3:
                score += 5
            
            # String concatenation obfuscation
            if command_line.count('"') > 4 or command_line.count("'") > 4:
                score += 5
            
            return min(20, score)
            
        except Exception:
            return 0
    
    async def _analyze_network_behavior(self, event_data) -> Optional[BehaviorPattern]:
        """Analyze network behavior patterns"""
        try:
            dest_ip = getattr(event_data, 'destination_ip', '')
            dest_port = getattr(event_data, 'destination_port', 0)
            protocol = getattr(event_data, 'protocol', '')
            
            suspicious_patterns = []
            risk_score = 0
            
            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337]
            if dest_port in suspicious_ports:
                suspicious_patterns.append(f"Suspicious port: {dest_port}")
                risk_score += 30
            
            # Check for common backdoor ports
            backdoor_ports = [22, 23, 3389, 5900]
            if dest_port in backdoor_ports and self._is_external_ip(dest_ip):
                suspicious_patterns.append(f"External access on port: {dest_port}")
                risk_score += 20
            
            # Check for data exfiltration patterns
            if protocol == 'TCP' and dest_port in [80, 443, 53]:
                # Could be DNS tunneling or HTTP exfiltration
                suspicious_patterns.append("Potential data exfiltration")
                risk_score += 15
            
            if risk_score >= 20:
                pattern_id = self._generate_pattern_id(event_data)
                
                return BehaviorPattern(
                    pattern_id=pattern_id,
                    pattern_type='network_behavior',
                    features=[dest_port, risk_score, len(suspicious_patterns)],
                    confidence=min(0.9, risk_score / 100.0),
                    risk_score=risk_score,
                    description=f"Suspicious network behavior: {', '.join(suspicious_patterns)}",
                    mitre_tactics=['Command and Control'],
                    mitre_techniques=['T1071']
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Network behavior analysis failed: {e}")
            return None
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private)"""
        try:
            private_ranges = ['10.', '172.16.', '192.168.', '127.', '169.254.']
            return not any(ip.startswith(prefix) for prefix in private_ranges)
        except:
            return False
    
    async def _analyze_file_behavior(self, event_data) -> Optional[BehaviorPattern]:
        """Analyze file behavior patterns"""
        try:
            file_path = getattr(event_data, 'file_path', '')
            file_operation = getattr(event_data, 'file_operation', '')
            
            suspicious_patterns = []
            risk_score = 0
            
            # Check for suspicious file locations
            suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/proc/']
            if any(path in file_path for path in suspicious_paths):
                if file_operation in ['CREATE', 'WRITE']:
                    suspicious_patterns.append(f"File creation in suspicious location: {file_path}")
                    risk_score += 25
            
            # Check for system file modifications
            system_paths = ['/etc/', '/usr/bin/', '/bin/', '/sbin/']
            if any(path in file_path for path in system_paths):
                if file_operation in ['MODIFY', 'DELETE']:
                    suspicious_patterns.append(f"System file modification: {file_path}")
                    risk_score += 30
            
            # Check for hidden file creation
            if '/.ssh/' in file_path or 'authorized_keys' in file_path:
                suspicious_patterns.append("SSH key manipulation")
                risk_score += 35
            
            # Check for log tampering
            if '/var/log/' in file_path and file_operation == 'DELETE':
                suspicious_patterns.append("Log file deletion")
                risk_score += 40
            
            if risk_score >= 20:
                pattern_id = self._generate_pattern_id(event_data)
                
                return BehaviorPattern(
                    pattern_id=pattern_id,
                    pattern_type='file_behavior',
                    features=[risk_score, len(suspicious_patterns)],
                    confidence=min(0.9, risk_score / 100.0),
                    risk_score=risk_score,
                    description=f"Suspicious file behavior: {', '.join(suspicious_patterns)}",
                    mitre_tactics=['Defense Evasion', 'Persistence'],
                    mitre_techniques=['T1070', 'T1543']
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ File behavior analysis failed: {e}")
            return None
    
    def _generate_pattern_id(self, event_data) -> str:
        """Generate unique pattern ID"""
        try:
            data_str = f"{event_data.event_type}_{event_data.event_timestamp}_{getattr(event_data, 'process_name', '')}_{getattr(event_data, 'file_path', '')}_{getattr(event_data, 'destination_ip', '')}"
            return hashlib.md5(data_str.encode()).hexdigest()[:16]
        except:
            return f"pattern_{int(time.time())}"
    
    async def detect_anomalies(self) -> List[AnomalyDetection]:
        """Detect behavioral anomalies using statistical analysis"""
        try:
            anomalies = []
            
            # Analyze process creation rates
            process_anomalies = await self._detect_process_anomalies()
            anomalies.extend(process_anomalies)
            
            # Analyze network connection patterns
            network_anomalies = await self._detect_network_anomalies()
            anomalies.extend(network_anomalies)
            
            # Analyze file access patterns
            file_anomalies = await self._detect_file_anomalies()
            anomalies.extend(file_anomalies)
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"❌ Anomaly detection failed: {e}")
            return []
    
    async def _detect_process_anomalies(self) -> List[AnomalyDetection]:
        """Detect process-related anomalies"""
        try:
            anomalies = []
            
            # Calculate process creation rate
            recent_processes = [e for e in self.process_events 
                             if (datetime.now() - e.event_timestamp).total_seconds() < self.analysis_window]
            
            current_rate = len(recent_processes) / (self.analysis_window / 60)  # per minute
            
            # Get baseline
            baseline_key = 'process_creation_rate'
            if baseline_key in self.baseline_metrics:
                baseline = self.baseline_metrics[baseline_key]
                deviation = abs(current_rate - baseline['mean']) / baseline['std']
                
                if deviation > self.anomaly_threshold:
                    anomalies.append(AnomalyDetection(
                        entity_id='system',
                        entity_type='process_creation',
                        anomaly_type='rate_anomaly',
                        baseline_value=baseline['mean'],
                        current_value=current_rate,
                        deviation_score=deviation,
                        timestamp=datetime.now()
                    ))
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"❌ Process anomaly detection failed: {e}")
            return []
    
    async def _detect_network_anomalies(self) -> List[AnomalyDetection]:
        """Detect network-related anomalies"""
        try:
            anomalies = []
            
            # Check for unusual connection patterns
            recent_connections = [e for e in self.network_events 
                                if (datetime.now() - e.event_timestamp).total_seconds() < self.analysis_window]
            
            # Group by destination IP
            ip_counts = defaultdict(int)
            for event in recent_connections:
                dest_ip = getattr(event, 'destination_ip', '')
                if dest_ip:
                    ip_counts[dest_ip] += 1
            
            # Check for beaconing behavior (repeated connections to same IP)
            for ip, count in ip_counts.items():
                if count > 10:  # More than 10 connections in window
                    anomalies.append(AnomalyDetection(
                        entity_id=ip,
                        entity_type='network_connection',
                        anomaly_type='beaconing',
                        baseline_value=1.0,
                        current_value=count,
                        deviation_score=count / 10.0,
                        timestamp=datetime.now()
                    ))
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"❌ Network anomaly detection failed: {e}")
            return []
    
    async def _detect_file_anomalies(self) -> List[AnomalyDetection]:
        """Detect file-related anomalies"""
        try:
            anomalies = []
            
            # Check for mass file operations (potential ransomware)
            recent_files = [e for e in self.file_events 
                          if (datetime.now() - e.event_timestamp).total_seconds() < self.analysis_window]
            
            # Count file operations by type
            operation_counts = defaultdict(int)
            for event in recent_files:
                operation = getattr(event, 'file_operation', '')
                if operation:
                    operation_counts[operation] += 1
            
            # Check for mass file creation/modification
            if operation_counts.get('CREATE', 0) > 50:
                anomalies.append(AnomalyDetection(
                    entity_id='filesystem',
                    entity_type='file_operation',
                    anomaly_type='mass_file_creation',
                    baseline_value=10.0,
                    current_value=operation_counts['CREATE'],
                    deviation_score=operation_counts['CREATE'] / 10.0,
                    timestamp=datetime.now()
                ))
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"❌ File anomaly detection failed: {e}")
            return []
    
    async def update_baseline_metrics(self):
        """Update baseline metrics for anomaly detection"""
        try:
            # Calculate process creation baseline
            if len(self.process_events) > 100:
                rates = []
                for i in range(0, len(self.process_events), 60):
                    window_events = list(self.process_events)[i:i+60]
                    rate = len(window_events)
                    rates.append(rate)
                
                if rates:
                    self.baseline_metrics['process_creation_rate'] = {
                        'mean': np.mean(rates),
                        'std': max(np.std(rates), 1.0),  # Prevent division by zero
                        'updated': datetime.now()
                    }
            
            # Update other baselines...
            self.logger.debug("Baseline metrics updated")
            
        except Exception as e:
            self.logger.error(f"❌ Baseline update failed: {e}")
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get comprehensive threat summary"""
        try:
            return {
                'total_patterns_detected': len(self.known_patterns),
                'suspicious_patterns': len(self.suspicious_patterns),
                'high_risk_events': len([p for p in self.known_patterns.values() if p.risk_score >= 70]),
                'mitre_techniques_detected': len(set(
                    tech for pattern in self.known_patterns.values() 
                    for tech in pattern.mitre_techniques
                )),
                'last_analysis': datetime.now().isoformat(),
                'analysis_enabled': self.enabled
            }
        except Exception as e:
            self.logger.error(f"❌ Threat summary generation failed: {e}")
            return {}
    
    def get_status(self) -> Dict[str, Any]:
        """Get behavior analyzer status"""
        return {
            'analyzer_type': 'behavior_analysis',
            'enabled': self.enabled,
            'process_events_buffered': len(self.process_events),
            'network_events_buffered': len(self.network_events),
            'file_events_buffered': len(self.file_events),
            'known_patterns': len(self.known_patterns),
            'suspicious_patterns': len(self.suspicious_patterns),
            'baseline_metrics': len(self.baseline_metrics),
            'mitre_techniques_mapped': len(self.mitre_mapping)
        }