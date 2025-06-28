# agent/utils/security_notifications.py - ENHANCED Linux Security Notifications
"""
ENHANCED Linux Security Alert Notification System
Hiển thị cảnh báo chi tiết về vi phạm bảo mật cho người dùng Linux
"""

import logging
import threading
import time
import json
import os
import sys
import asyncio
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import traceback

class LinuxSecurityNotifier:
    """Enhanced Linux Security Alert Notifier với thông tin vi phạm chi tiết"""
    
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        
        # Server communication reference
        self.communication = None
        
        # Linux notification settings
        self.enabled = True
        self.show_server_rules = True
        self.show_local_rules = True
        self.show_risk_based_alerts = True
        self.show_on_screen = True
        self.play_sound = True
        self.alert_duration = 15  # 15 seconds for Linux
        
        # Linux desktop environment detection
        self.desktop_environment = self._detect_desktop_environment()
        self.notification_methods = self._detect_notification_methods()
        
        # Alert tracking
        self.total_alerts_received = 0
        self.total_alerts_displayed = 0
        self.server_rule_alerts = 0
        self.local_rule_alerts = 0
        self.risk_based_alerts = 0
        self.last_alert_time = None
        self.acknowledged_alerts = set()
        
        # Alert deduplication
        self.recent_alerts = {}
        self.alert_cooldown = 30  # 30 seconds between similar alerts
        
        # Sound configuration
        self.sound_enabled = self._check_sound_support()
        self.sound_file = self._find_alert_sound()
        
        # Display detection
        self.display_available = self._check_display_available()
        
        # ✅ ENHANCED: Rule violation mapping
        self.violation_descriptions = {
            'process_violation': {
                'title': '🚨 Process Security Violation',
                'description': 'Suspicious process activity detected',
                'details': 'A process on your system has triggered security rules'
            },
            'file_violation': {
                'title': '📁 File Security Violation', 
                'description': 'Unauthorized file access or modification',
                'details': 'Files on your system have been accessed or modified suspiciously'
            },
            'network_violation': {
                'title': '🌐 Network Security Violation',
                'description': 'Suspicious network activity detected',
                'details': 'Unusual network connections or data transfer detected'
            },
            'authentication_violation': {
                'title': '🔐 Authentication Security Violation',
                'description': 'Authentication security breach detected',
                'details': 'Suspicious login attempts or credential misuse detected'
            },
            'system_violation': {
                'title': '⚙️ System Security Violation',
                'description': 'System-level security breach detected',
                'details': 'Critical system components or configurations have been compromised'
            },
            'privilege_escalation': {
                'title': '⬆️ Privilege Escalation Detected',
                'description': 'Unauthorized privilege escalation attempt',
                'details': 'An attempt to gain higher system privileges has been detected'
            },
            'malware_detection': {
                'title': '🦠 Malware Detection',
                'description': 'Malicious software detected',
                'details': 'Potential malware or malicious code has been identified'
            },
            'data_exfiltration': {
                'title': '📤 Data Exfiltration Attempt',
                'description': 'Potential data theft attempt',
                'details': 'Suspicious data transfer that may indicate data theft'
            },
            'persistence_mechanism': {
                'title': '🔄 Persistence Mechanism Detected',
                'description': 'Malware persistence attempt',
                'details': 'Software is attempting to maintain persistence on your system'
            },
            'lateral_movement': {
                'title': '↔️ Lateral Movement Detected',
                'description': 'Network lateral movement attempt',
                'details': 'Suspicious movement across network systems detected'
            }
        }
        
        self.logger.info(f"🐧 Enhanced Linux Security Notifier initialized")
        self.logger.info(f"   🖥️ Desktop Environment: {self.desktop_environment}")
        self.logger.info(f"   🔔 Notification Methods: {', '.join(self.notification_methods)}")
        self.logger.info(f"   🔊 Sound Support: {self.sound_enabled}")
        self.logger.info(f"   📺 Display Available: {self.display_available}")
    
    def _detect_desktop_environment(self) -> str:
        """Detect Linux desktop environment"""
        try:
            # Check common environment variables
            env_vars = [
                ('XDG_CURRENT_DESKTOP', ['GNOME', 'KDE', 'XFCE', 'MATE', 'LXDE', 'Unity', 'Cinnamon']),
                ('DESKTOP_SESSION', ['gnome', 'kde', 'xfce', 'mate', 'lxde', 'unity', 'cinnamon']),
                ('KDE_FULL_SESSION', ['true']),
                ('GNOME_DESKTOP_SESSION_ID', ['*'])
            ]
            
            for env_var, values in env_vars:
                env_value = os.environ.get(env_var, '').lower()
                if env_value:
                    for value in values:
                        if value.lower() in env_value or value == '*':
                            return value.upper() if value != '*' else 'GNOME'
            
            # Check for specific processes
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                processes = result.stdout.lower()
                
                if 'gnome-session' in processes:
                    return 'GNOME'
                elif 'kded' in processes or 'plasma' in processes:
                    return 'KDE'
                elif 'xfce4-session' in processes:
                    return 'XFCE'
                elif 'mate-session' in processes:
                    return 'MATE'
            except:
                pass
            
            return 'Unknown'
            
        except Exception as e:
            self.logger.debug(f"Could not detect desktop environment: {e}")
            return 'Unknown'
    
    def _detect_notification_methods(self) -> List[str]:
        """Detect available notification methods on Linux"""
        methods = []
        
        try:
            # Check for notify-send (most common)
            if self._command_available('notify-send'):
                methods.append('notify-send')
            
            # Check for kdialog (KDE)
            if self._command_available('kdialog'):
                methods.append('kdialog')
            
            # Check for zenity (GNOME/GTK)
            if self._command_available('zenity'):
                methods.append('zenity')
            
            # Check for xmessage (X11 fallback)
            if self._command_available('xmessage'):
                methods.append('xmessage')
            
            # Check for wall command (system-wide)
            if self._command_available('wall'):
                methods.append('wall')
            
            # Console/terminal fallback
            methods.append('console')
            
            return methods
            
        except Exception as e:
            self.logger.error(f"Error detecting notification methods: {e}")
            return ['console']
    
    def _command_available(self, command: str) -> bool:
        """Check if a command is available"""
        try:
            result = subprocess.run(['which', command], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_sound_support(self) -> bool:
        """Check if sound playback is available"""
        try:
            players = ['paplay', 'aplay', 'play', 'mpg123', 'ogg123']
            for player in players:
                if self._command_available(player):
                    return True
            return False
        except:
            return False
    
    def _find_alert_sound(self) -> Optional[str]:
        """Find suitable alert sound file"""
        try:
            sound_paths = [
                '/usr/share/sounds/alsa/Front_Left.wav',
                '/usr/share/sounds/sound-icons/bell.wav',
                '/usr/share/sounds/generic/bell.wav',
                '/usr/share/sounds/freedesktop/stereo/bell.oga',
                '/usr/share/sounds/freedesktop/stereo/audio-volume-change.oga',
                '/usr/share/sounds/ubuntu/stereo/bell.ogg',
                '/System/Library/Sounds/Ping.aiff'
            ]
            
            for sound_path in sound_paths:
                if os.path.exists(sound_path):
                    return sound_path
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Could not find alert sound: {e}")
            return None
    
    def _check_display_available(self) -> bool:
        """Check if display is available for GUI notifications"""
        try:
            return bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))
        except:
            return False
    
    def set_communication(self, communication):
        """Set communication reference for threat detection"""
        self.communication = communication
        if hasattr(self.communication, 'add_alert_handler'):
            self.communication.add_alert_handler(self)
            self.logger.info("✅ Communication reference set - alert handler registered")
    
    async def handle_security_alert(self, alert):
        """✅ ENHANCED: Handle security alert from server với thông tin chi tiết"""
        try:
            if not self.enabled:
                return
            
            self.logger.warning(f"🚨 PROCESSING SECURITY ALERT: {alert.title}")
            
            # Create enhanced alert display
            enhanced_alert = await self._create_enhanced_alert_display(alert)
            
            # Check for duplicate alerts
            alert_key = self._generate_alert_key(enhanced_alert)
            if self._is_duplicate_alert(alert_key):
                self.logger.debug(f"Skipping duplicate Linux alert: {alert_key}")
                return
            
            # Update statistics
            self.total_alerts_received += 1
            self._update_alert_statistics(enhanced_alert)
            
            # Display alert using available methods
            success = await self._display_enhanced_alert(enhanced_alert)
            
            if success:
                self.total_alerts_displayed += 1
                self.last_alert_time = datetime.now()
                self._track_recent_alert(alert_key)
                
                self.logger.warning(f"🚨 LINUX SECURITY ALERT DISPLAYED: {enhanced_alert['title']}")
                self.logger.warning(f"   📋 Violation: {enhanced_alert['violation_type']}")
                self.logger.warning(f"   ⚠️ Severity: {enhanced_alert['severity']}")
                self.logger.warning(f"   📊 Risk Score: {enhanced_alert['risk_score']}")
            
        except Exception as e:
            self.logger.error(f"❌ Error handling security alert: {e}")
    
    async def _create_enhanced_alert_display(self, alert) -> Dict[str, Any]:
        """✅ ENHANCED: Tạo thông tin hiển thị cảnh báo chi tiết"""
        try:
            # Determine violation type from alert details
            violation_type = self._determine_violation_type(alert)
            violation_info = self.violation_descriptions.get(violation_type, {
                'title': '🚨 Security Violation',
                'description': 'Security rule violation detected',
                'details': 'A security policy has been violated'
            })
            
            # Create detailed violation explanation
            violation_explanation = self._create_violation_explanation(alert, violation_type)
            
            # Create action recommendations
            recommended_actions = self._get_recommended_actions(alert, violation_type)
            
            # Format detailed message
            detailed_message = self._format_detailed_message(alert, violation_explanation, recommended_actions)
            
            # Determine severity and urgency
            severity_info = self._analyze_severity(alert)
            
            enhanced_alert = {
                'alert_id': alert.alert_id,
                'title': violation_info['title'],
                'violation_type': violation_type,
                'violation_description': violation_info['description'],
                'violation_details': violation_info['details'],
                'violation_explanation': violation_explanation,
                'detailed_message': detailed_message,
                'recommended_actions': recommended_actions,
                'severity': alert.severity,
                'urgency': severity_info['urgency'],
                'risk_score': alert.risk_score,
                'rule_name': alert.rule_name,
                'rule_description': alert.rule_description,
                'threat_description': alert.threat_description,
                'timestamp': alert.timestamp,
                'requires_acknowledgment': alert.requires_acknowledgment,
                'display_popup': alert.display_popup,
                'play_sound': alert.play_sound,
                'action_required': alert.action_required,
                'event_details': alert.event_details,
                'original_alert': alert
            }
            
            return enhanced_alert
            
        except Exception as e:
            self.logger.error(f"❌ Error creating enhanced alert display: {e}")
            return {
                'title': '🚨 Linux Security Alert',
                'violation_type': 'unknown',
                'detailed_message': 'Security violation detected',
                'severity': alert.severity if alert else 'Medium',
                'risk_score': alert.risk_score if alert else 50,
                'timestamp': datetime.now()
            }
    
    def _determine_violation_type(self, alert) -> str:
        """Xác định loại vi phạm từ alert"""
        try:
            # Analyze rule name and description
            rule_name = alert.rule_name.lower()
            rule_desc = alert.rule_description.lower()
            threat_desc = alert.threat_description.lower()
            
            # Check event details for more context
            event_details = alert.event_details or {}
            event_type = event_details.get('event_type', '').lower()
            
            # Determine violation type based on keywords
            if any(keyword in rule_name + rule_desc + threat_desc for keyword in ['process', 'executable', 'command']):
                if any(keyword in rule_name + rule_desc for keyword in ['privilege', 'escalation', 'sudo', 'root']):
                    return 'privilege_escalation'
                return 'process_violation'
            
            elif any(keyword in rule_name + rule_desc + threat_desc for keyword in ['file', 'filesystem', 'directory']):
                return 'file_violation'
            
            elif any(keyword in rule_name + rule_desc + threat_desc for keyword in ['network', 'connection', 'socket', 'port']):
                if any(keyword in rule_name + rule_desc for keyword in ['exfiltration', 'transfer', 'upload']):
                    return 'data_exfiltration'
                elif any(keyword in rule_name + rule_desc for keyword in ['lateral', 'movement', 'pivot']):
                    return 'lateral_movement'
                return 'network_violation'
            
            elif any(keyword in rule_name + rule_desc + threat_desc for keyword in ['auth', 'login', 'credential', 'password']):
                return 'authentication_violation'
            
            elif any(keyword in rule_name + rule_desc + threat_desc for keyword in ['malware', 'virus', 'trojan', 'backdoor']):
                return 'malware_detection'
            
            elif any(keyword in rule_name + rule_desc + threat_desc for keyword in ['persistence', 'startup', 'autostart', 'cron']):
                return 'persistence_mechanism'
            
            elif any(keyword in rule_name + rule_desc + threat_desc for keyword in ['system', 'kernel', 'service']):
                return 'system_violation'
            
            # Check by event type
            elif event_type == 'process':
                return 'process_violation'
            elif event_type == 'file':
                return 'file_violation'
            elif event_type == 'network':
                return 'network_violation'
            elif event_type == 'authentication':
                return 'authentication_violation'
            elif event_type == 'system':
                return 'system_violation'
            
            return 'system_violation'  # Default
            
        except Exception as e:
            self.logger.debug(f"Error determining violation type: {e}")
            return 'system_violation'
    
    def _create_violation_explanation(self, alert, violation_type: str) -> str:
        """Tạo giải thích chi tiết về vi phạm"""
        try:
            event_details = alert.event_details or {}
            explanations = []
            
            # Basic violation info
            explanations.append(f"Rule Triggered: {alert.rule_name}")
            explanations.append(f"Threat Level: {alert.severity} (Risk Score: {alert.risk_score}/100)")
            
            # Specific details based on violation type
            if violation_type == 'process_violation':
                if 'process_name' in event_details:
                    explanations.append(f"Suspicious Process: {event_details['process_name']}")
                if 'command_line' in event_details:
                    explanations.append(f"Command: {event_details['command_line'][:100]}...")
                if 'parent_process' in event_details:
                    explanations.append(f"Parent Process: {event_details['parent_process']}")
            
            elif violation_type == 'file_violation':
                if 'file_path' in event_details:
                    explanations.append(f"File Affected: {event_details['file_path']}")
                if 'file_operation' in event_details:
                    explanations.append(f"Operation: {event_details['file_operation']}")
                if 'file_size' in event_details:
                    explanations.append(f"File Size: {event_details['file_size']} bytes")
            
            elif violation_type == 'network_violation':
                if 'source_ip' in event_details:
                    explanations.append(f"Source: {event_details['source_ip']}")
                if 'destination_ip' in event_details:
                    explanations.append(f"Destination: {event_details['destination_ip']}")
                if 'destination_port' in event_details:
                    explanations.append(f"Port: {event_details['destination_port']}")
                if 'protocol' in event_details:
                    explanations.append(f"Protocol: {event_details['protocol']}")
            
            elif violation_type == 'authentication_violation':
                if 'username' in event_details:
                    explanations.append(f"User Account: {event_details['username']}")
                if 'source_ip' in event_details:
                    explanations.append(f"Login Source: {event_details['source_ip']}")
                if 'login_type' in event_details:
                    explanations.append(f"Login Method: {event_details['login_type']}")
            
            elif violation_type == 'privilege_escalation':
                if 'target_user' in event_details:
                    explanations.append(f"Target User: {event_details['target_user']}")
                if 'escalation_method' in event_details:
                    explanations.append(f"Method: {event_details['escalation_method']}")
                explanations.append("Impact: Unauthorized privilege elevation detected")
            
            # Add threat description
            if alert.threat_description:
                explanations.append(f"Threat Analysis: {alert.threat_description}")
            
            return '\n'.join(explanations)
            
        except Exception as e:
            self.logger.debug(f"Error creating violation explanation: {e}")
            return f"Rule: {alert.rule_name}\nThreat: {alert.threat_description}"
    
    def _get_recommended_actions(self, alert, violation_type: str) -> List[str]:
        """Tạo danh sách hành động khuyến nghị"""
        try:
            actions = []
            
            # General actions for all violations
            actions.append("✅ Investigate immediately")
            actions.append("📋 Check system logs for related activity")
            actions.append("🔍 Monitor system for additional suspicious behavior")
            
            # Specific actions based on violation type
            if violation_type == 'process_violation':
                actions.extend([
                    "🛑 Consider terminating suspicious process",
                    "🔍 Analyze process parent-child relationships",
                    "📊 Check process network connections",
                    "🔒 Verify process digital signatures"
                ])
            
            elif violation_type == 'file_violation':
                actions.extend([
                    "📁 Backup affected files immediately",
                    "🔒 Check file permissions and ownership",
                    "🛡️ Scan files for malware",
                    "📝 Review file access logs"
                ])
            
            elif violation_type == 'network_violation':
                actions.extend([
                    "🌐 Block suspicious IP addresses",
                    "🔍 Analyze network traffic patterns",
                    "🛡️ Check firewall rules",
                    "📊 Monitor bandwidth usage"
                ])
            
            elif violation_type == 'authentication_violation':
                actions.extend([
                    "🔐 Force password reset for affected accounts",
                    "🚫 Temporarily disable compromised accounts",
                    "🔍 Review authentication logs",
                    "💳 Check for unauthorized access"
                ])
            
            elif violation_type == 'privilege_escalation':
                actions.extend([
                    "⛔ Immediately revoke elevated privileges",
                    "🔍 Audit sudo/su usage logs",
                    "🔒 Review user permissions",
                    "🛡️ Check for privilege escalation tools"
                ])
            
            elif violation_type == 'malware_detection':
                actions.extend([
                    "🦠 Isolate affected system immediately",
                    "🧹 Run full antimalware scan",
                    "🔍 Check for additional malware variants",
                    "💾 Create forensic image if needed"
                ])
            
            elif violation_type == 'data_exfiltration':
                actions.extend([
                    "🚫 Block outbound connections immediately",
                    "🔍 Identify what data was accessed",
                    "📊 Analyze data transfer logs",
                    "🔒 Encrypt sensitive data"
                ])
            
            # Severity-based actions
            if alert.severity in ['High', 'Critical']:
                actions.extend([
                    "📞 Contact security team immediately",
                    "📝 Document incident details",
                    "🔒 Consider system isolation"
                ])
            
            # Risk score based actions
            if alert.risk_score >= 80:
                actions.extend([
                    "🚨 Escalate to emergency response team",
                    "💾 Preserve evidence",
                    "📋 Prepare incident report"
                ])
            
            return actions[:8]  # Limit to 8 actions for display
            
        except Exception as e:
            self.logger.debug(f"Error getting recommended actions: {e}")
            return [
                "✅ Investigate immediately",
                "📋 Check system logs",
                "🔍 Monitor for additional activity",
                "📞 Contact security team if needed"
            ]
    
    def _format_detailed_message(self, alert, violation_explanation: str, recommended_actions: List[str]) -> str:
        """Format detailed message for display"""
        try:
            message_parts = []
            
            # Title section
            message_parts.append("🚨 SECURITY VIOLATION DETECTED")
            message_parts.append("=" * 50)
            
            # Violation details
            message_parts.append("📋 VIOLATION DETAILS:")
            message_parts.append(violation_explanation)
            message_parts.append("")
            
            # Recommended actions
            message_parts.append("🔧 RECOMMENDED ACTIONS:")
            for i, action in enumerate(recommended_actions, 1):
                message_parts.append(f"{i}. {action}")
            message_parts.append("")
            
            # Timing info
            message_parts.append(f"⏰ Detection Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if alert.requires_acknowledgment:
                message_parts.append("")
                message_parts.append("⚠️ THIS ALERT REQUIRES ACKNOWLEDGMENT")
            
            return '\n'.join(message_parts)
            
        except Exception as e:
            self.logger.debug(f"Error formatting detailed message: {e}")
            return f"Security violation detected: {alert.rule_name}"
    
    def _analyze_severity(self, alert) -> Dict[str, str]:
        """Analyze severity and determine urgency"""
        try:
            severity = alert.severity
            risk_score = alert.risk_score
            
            if severity == 'Critical' or risk_score >= 90:
                urgency = 'critical'
                priority = 'immediate'
            elif severity == 'High' or risk_score >= 70:
                urgency = 'normal'
                priority = 'high'
            elif severity == 'Medium' or risk_score >= 50:
                urgency = 'normal'
                priority = 'medium'
            else:
                urgency = 'low'
                priority = 'low'
            
            return {
                'urgency': urgency,
                'priority': priority
            }
            
        except Exception as e:
            self.logger.debug(f"Error analyzing severity: {e}")
            return {'urgency': 'normal', 'priority': 'medium'}
    
    async def _display_enhanced_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Display enhanced alert using available Linux methods"""
        try:
            success = False
            
            # Try GUI notifications first
            if self.display_available and self.show_on_screen:
                success = await self._show_enhanced_gui_notification(alert_data)
            
            # Always log to console with detailed info
            self._show_enhanced_console_alert(alert_data)
            
            # Play sound if enabled
            if self.play_sound and self.sound_enabled:
                self._play_alert_sound()
            
            # Try system-wide notification if critical
            if alert_data.get('severity') == 'Critical':
                self._show_enhanced_system_alert(alert_data)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error displaying enhanced alert: {e}")
            return False
    
    async def _show_enhanced_gui_notification(self, alert_data: Dict[str, Any]) -> bool:
        """Show enhanced GUI notification với thông tin chi tiết"""
        try:
            title = alert_data['title']
            violation_type = alert_data['violation_type'] 
            detailed_message = alert_data['detailed_message']
            urgency = alert_data.get('urgency', 'normal')
            
            # Create shorter message for GUI
            gui_message = self._create_gui_message(alert_data)
            
            # Try notify-send first (most common)
            if 'notify-send' in self.notification_methods:
                try:
                    cmd = [
                        'notify-send',
                        '--urgency', urgency,
                        '--expire-time', str(self.alert_duration * 1000),
                        '--icon', 'security-high',
                        '--category', 'security',
                        title,
                        gui_message
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    if result.returncode == 0:
                        return True
                except Exception as e:
                    self.logger.debug(f"notify-send failed: {e}")
            
            # Try KDE kdialog
            if 'kdialog' in self.notification_methods:
                try:
                    cmd = [
                        'kdialog',
                        '--title', title,
                        '--passivepopup', f"{title}\n{gui_message}",
                        str(self.alert_duration)
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    if result.returncode == 0:
                        return True
                except Exception as e:
                    self.logger.debug(f"kdialog failed: {e}")
            
            # Try GNOME zenity
            if 'zenity' in self.notification_methods:
                try:
                    cmd = [
                        'zenity',
                        '--notification',
                        '--text', f"{title}\n{gui_message}"
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    if result.returncode == 0:
                        return True
                except Exception as e:
                    self.logger.debug(f"zenity failed: {e}")
            
            # Try xmessage as fallback với detailed info
            if 'xmessage' in self.notification_methods:
                try:
                    detailed_gui_message = f"{title}\n\n{gui_message}\n\nViolation: {violation_type}\nSeverity: {alert_data['severity']}\nRisk Score: {alert_data['risk_score']}/100"
                    
                    cmd = [
                        'xmessage',
                        '-center',
                        '-timeout', str(self.alert_duration),
                        detailed_gui_message
                    ]
                    
                    subprocess.Popen(cmd)  # Don't wait for user interaction
                    return True
                except Exception as e:
                    self.logger.debug(f"xmessage failed: {e}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error showing enhanced GUI notification: {e}")
            return False
    
    def _create_gui_message(self, alert_data: Dict[str, Any]) -> str:
        """Create shorter message for GUI notifications"""
        try:
            parts = []
            
            parts.append(f"Violation: {alert_data['violation_description']}")
            parts.append(f"Rule: {alert_data['rule_name']}")
            parts.append(f"Severity: {alert_data['severity']} (Risk: {alert_data['risk_score']}/100)")
            
            # Add specific details based on violation type
            event_details = alert_data.get('event_details', {})
            if event_details.get('process_name'):
                parts.append(f"Process: {event_details['process_name']}")
            elif event_details.get('file_path'):
                parts.append(f"File: {os.path.basename(event_details['file_path'])}")
            elif event_details.get('destination_ip'):
                parts.append(f"Network: {event_details['destination_ip']}")
            
            parts.append("Check console for full details")
            
            return '\n'.join(parts)
            
        except Exception as e:
            self.logger.debug(f"Error creating GUI message: {e}")
            return f"Security violation: {alert_data.get('rule_name', 'Unknown')}"
    
    def _show_enhanced_console_alert(self, alert_data: Dict[str, Any]):
        """Show enhanced alert in console với thông tin đầy đủ"""
        try:
            print("\n" + "=" * 80)
            print(f"🚨 LINUX SECURITY VIOLATION - {alert_data['severity'].upper()}")
            print("=" * 80)
            print(f"🕒 Time: {alert_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"🏷️ Alert ID: {alert_data['alert_id']}")
            print(f"⚠️ Violation Type: {alert_data['violation_type'].upper()}")
            print(f"📊 Risk Score: {alert_data['risk_score']}/100")
            print("-" * 80)
            print("📋 VIOLATION DETAILS:")
            print(alert_data['violation_explanation'])
            print("-" * 80)
            print("🔧 RECOMMENDED ACTIONS:")
            for i, action in enumerate(alert_data['recommended_actions'], 1):
                print(f"{i}. {action}")
            print("=" * 80)
            
            # Also log the alert
            self.logger.warning(f"🚨 {alert_data['title']}")
            self.logger.warning(f"   📋 Violation: {alert_data['violation_type']}")
            self.logger.warning(f"   ⚠️ Severity: {alert_data['severity']}")
            self.logger.warning(f"   📊 Risk Score: {alert_data['risk_score']}/100")
            self.logger.warning(f"   📝 Rule: {alert_data['rule_name']}")
            
        except Exception as e:
            self.logger.error(f"Error showing enhanced console alert: {e}")
    
    def _show_enhanced_system_alert(self, alert_data: Dict[str, Any]):
        """Show enhanced system-wide alert for critical threats"""
        try:
            # Use wall command for system-wide notification
            if 'wall' in self.notification_methods:
                try:
                    message = f"""
🚨 CRITICAL SECURITY ALERT 🚨
Violation: {alert_data['violation_type'].upper()}
Rule: {alert_data['rule_name']}
Severity: {alert_data['severity']} (Risk: {alert_data['risk_score']}/100)
Time: {alert_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}

IMMEDIATE ACTION REQUIRED - CHECK SYSTEM LOGS
Contact your system administrator immediately.
"""
                    subprocess.run(['wall', message], input=message, text=True, timeout=5)
                except Exception as e:
                    self.logger.debug(f"wall command failed: {e}")
            
        except Exception as e:
            self.logger.debug(f"Error showing enhanced system alert: {e}")
    
    def _play_alert_sound(self):
        """Play alert sound"""
        try:
            if not self.sound_file:
                return
            
            # Try different audio players
            players = [
                ['paplay', self.sound_file],
                ['aplay', self.sound_file],
                ['play', self.sound_file],
                ['mpg123', self.sound_file]
            ]
            
            for player_cmd in players:
                try:
                    if self._command_available(player_cmd[0]):
                        subprocess.Popen(player_cmd, 
                                       stdout=subprocess.DEVNULL, 
                                       stderr=subprocess.DEVNULL)
                        break
                except:
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Error playing alert sound: {e}")
    
    # ... (keep existing methods for compatibility)
    def _generate_alert_key(self, alert_data: Dict[str, Any]) -> str:
        """Generate unique key for alert deduplication"""
        try:
            key_parts = [
                alert_data.get('violation_type', 'Unknown'),
                alert_data.get('rule_name', 'Unknown'),
                str(alert_data.get('risk_score', 0))
            ]
            return '-'.join(key_parts).lower()
        except:
            return f"alert-{time.time()}"
    
    def _is_duplicate_alert(self, alert_key: str) -> bool:
        """Check if alert is a duplicate within cooldown period"""
        try:
            current_time = time.time()
            
            if alert_key in self.recent_alerts:
                last_time = self.recent_alerts[alert_key]
                if current_time - last_time < self.alert_cooldown:
                    return True
            
            return False
            
        except:
            return False
    
    def _track_recent_alert(self, alert_key: str):
        """Track recent alert for deduplication"""
        try:
            current_time = time.time()
            self.recent_alerts[alert_key] = current_time
            
            # Clean old entries
            cutoff_time = current_time - self.alert_cooldown * 2
            self.recent_alerts = {
                key: timestamp for key, timestamp in self.recent_alerts.items()
                if timestamp > cutoff_time
            }
        except Exception as e:
            self.logger.debug(f"Error tracking recent alert: {e}")
    
    def _update_alert_statistics(self, alert_data: Dict[str, Any]):
        """Update alert statistics"""
        try:
            violation_type = alert_data.get('violation_type', 'general')
            
            if 'server' in alert_data.get('rule_name', '').lower():
                self.server_rule_alerts += 1
            else:
                self.local_rule_alerts += 1
                
        except Exception as e:
            self.logger.debug(f"Error updating alert statistics: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get notification statistics"""
        return {
            'total_alerts_received': self.total_alerts_received,
            'total_alerts_displayed': self.total_alerts_displayed,
            'server_rule_alerts': self.server_rule_alerts,
            'local_rule_alerts': self.local_rule_alerts,
            'risk_based_alerts': self.risk_based_alerts,
            'acknowledged_alerts_count': len(self.acknowledged_alerts),
            'last_alert_time': self.last_alert_time.isoformat() if self.last_alert_time else None,
            'desktop_environment': self.desktop_environment,
            'notification_methods': self.notification_methods,
            'sound_enabled': self.sound_enabled,
            'display_available': self.display_available,
            'enabled': self.enabled,
            'violation_types_supported': list(self.violation_descriptions.keys()),
            'platform': 'linux'
        }
    
    # Legacy compatibility method
    async def process_threat_response(self, event_data, response_data: Dict[str, Any]):
        """Legacy compatibility for existing code"""
        try:
            if not self.enabled:
                return
            
            # Convert legacy format to new SecurityAlert format
            alert_id = f"legacy_{int(time.time())}"
            
            # Create a mock SecurityAlert object
            mock_alert = type('SecurityAlert', (), {
                'alert_id': alert_id,
                'alert_type': 'security_rule_violation',
                'severity': 'Medium',
                'title': '🚨 Security Threat Detected',
                'description': response_data.get('threat_description', 'Security threat detected'),
                'rule_name': response_data.get('rule_triggered', 'Security Rule'),
                'rule_description': response_data.get('rule_description', 'Security rule triggered'),
                'threat_description': response_data.get('threat_description', 'Potential security threat'),
                'risk_score': response_data.get('risk_score', 50),
                'event_details': {
                    'event_type': getattr(event_data, 'event_type', 'Unknown'),
                    'process_name': getattr(event_data, 'process_name', None),
                    'file_path': getattr(event_data, 'file_path', None),
                    'destination_ip': getattr(event_data, 'destination_ip', None)
                },
                'timestamp': datetime.now(),
                'requires_acknowledgment': response_data.get('risk_score', 50) >= 70,
                'display_popup': True,
                'play_sound': response_data.get('risk_score', 50) >= 70,
                'action_required': response_data.get('risk_score', 50) >= 70
            })()
            
            await self.handle_security_alert(mock_alert)
            
        except Exception as e:
            self.logger.error(f"❌ Error processing legacy threat response: {e}")


# Global instance for easy access
linux_notifier: Optional[LinuxSecurityNotifier] = None

def initialize_linux_notifier(config_manager=None) -> LinuxSecurityNotifier:
    """Initialize global Linux notifier instance"""
    global linux_notifier
    try:
        linux_notifier = LinuxSecurityNotifier(config_manager)
        return linux_notifier
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to initialize Linux notifier: {e}")
        return None

def get_linux_notifier() -> Optional[LinuxSecurityNotifier]:
    """Get global Linux notifier instance"""
    global linux_notifier
    return linux_notifier

def create_linux_notifier(config_manager=None) -> LinuxSecurityNotifier:
    """Create a new Linux notifier instance"""
    return LinuxSecurityNotifier(config_manager)

# Utility functions for external use
def show_security_alert(alert_data: Dict[str, Any]):
    """Show security alert using the global notifier"""
    global linux_notifier
    if linux_notifier:
        asyncio.create_task(linux_notifier.handle_security_alert(alert_data))

def get_notification_stats() -> Dict[str, Any]:
    """Get notification statistics from global notifier"""
    global linux_notifier
    if linux_notifier:
        return linux_notifier.get_stats()
    return {}

def is_notifier_available() -> bool:
    """Check if Linux notifier is available and initialized"""
    global linux_notifier
    return linux_notifier is not None and linux_notifier.enabled

# Export main classes and functions
__all__ = [
    'LinuxSecurityNotifier',
    'initialize_linux_notifier',
    'get_linux_notifier',
    'create_linux_notifier',
    'show_security_alert',
    'get_notification_stats',
    'is_notifier_available'
]