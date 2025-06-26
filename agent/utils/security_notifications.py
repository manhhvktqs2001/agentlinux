# agent/utils/security_notifications.py - Linux Security Notifications
"""
Linux Security Alert Notification System
Display security alerts on Linux desktop environments with multiple fallback methods
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
    """Linux Security Alert Notifier with multiple notification methods"""
    
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
        self.alert_duration = 10  # 10 seconds for Linux
        
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
        
        self.logger.info(f"🐧 Linux Security Notifier initialized")
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
            # Check for audio players
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
            # Common system sound locations
            sound_paths = [
                '/usr/share/sounds/alsa/Front_Left.wav',
                '/usr/share/sounds/sound-icons/bell.wav',
                '/usr/share/sounds/generic/bell.wav',
                '/usr/share/sounds/freedesktop/stereo/bell.oga',
                '/usr/share/sounds/freedesktop/stereo/audio-volume-change.oga',
                '/usr/share/sounds/ubuntu/stereo/bell.ogg',
                '/System/Library/Sounds/Ping.aiff'  # macOS compatibility
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
        if hasattr(self.communication, 'threats_detected_by_server'):
            self.logger.info("✅ Communication reference set for Linux threat detection")
    
    async def process_threat_response(self, event_data, response_data: Dict[str, Any]):
        """Process server response for threat detection"""
        try:
            if not self.enabled:
                return
            
            # Check if response indicates a threat
            threat_detected = response_data.get('threat_detected', False)
            risk_score = response_data.get('risk_score', 0)
            alerts_generated = response_data.get('alerts_generated', [])
            
            if threat_detected or risk_score >= 70 or alerts_generated:
                await self._create_and_show_alert(event_data, response_data)
                
        except Exception as e:
            self.logger.error(f"❌ Error processing Linux threat response: {e}")
    
    async def _create_and_show_alert(self, event_data, response_data: Dict[str, Any]):
        """Create and display Linux security alert"""
        try:
            # Create alert data
            alert_data = self._create_alert_data(event_data, response_data)
            
            # Check for duplicate alerts
            alert_key = self._generate_alert_key(alert_data)
            if self._is_duplicate_alert(alert_key):
                self.logger.debug(f"Skipping duplicate Linux alert: {alert_key}")
                return
            
            # Update statistics
            self.total_alerts_received += 1
            self._update_alert_statistics(alert_data)
            
            # Show alert using available methods
            success = await self._display_alert(alert_data)
            
            if success:
                self.total_alerts_displayed += 1
                self.last_alert_time = datetime.now()
                self._track_recent_alert(alert_key)
                
                self.logger.warning(f"🚨 LINUX SECURITY ALERT DISPLAYED: {alert_data['title']}")
            
        except Exception as e:
            self.logger.error(f"❌ Error creating Linux security alert: {e}")
    
    def _create_alert_data(self, event_data, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert data structure"""
        try:
            # Determine alert type and severity
            threat_detected = response_data.get('threat_detected', False)
            risk_score = response_data.get('risk_score', 0)
            rule_triggered = response_data.get('rule_triggered', '')
            alerts_generated = response_data.get('alerts_generated', [])
            
            # Determine alert category
            if rule_triggered:
                alert_type = 'Rule-Based Detection'
                category = 'server_rule'
            elif risk_score >= 70:
                alert_type = 'High Risk Activity'
                category = 'risk_based'
            elif alerts_generated:
                alert_type = 'Behavioral Detection'
                category = 'behavior'
            else:
                alert_type = 'Security Event'
                category = 'general'
            
            # Create alert title
            event_type = getattr(event_data, 'event_type', 'System')
            process_name = getattr(event_data, 'process_name', 'Unknown')
            
            title = f"🐧 Linux {alert_type}: {event_type}"
            
            # Create alert message
            message_parts = [
                f"Process: {process_name}",
                f"Event: {event_type} - {getattr(event_data, 'event_action', 'Unknown')}",
                f"Risk Score: {risk_score}/100"
            ]
            
            if rule_triggered:
                message_parts.append(f"Rule: {rule_triggered}")
            
            if hasattr(event_data, 'file_path') and event_data.file_path:
                message_parts.append(f"File: {event_data.file_path}")
            
            if hasattr(event_data, 'destination_ip') and event_data.destination_ip:
                message_parts.append(f"Network: {event_data.destination_ip}")
            
            # Determine severity
            if risk_score >= 90:
                severity = 'Critical'
                urgency = 'critical'
            elif risk_score >= 70:
                severity = 'High'
                urgency = 'normal'
            elif threat_detected:
                severity = 'Medium'
                urgency = 'normal'
            else:
                severity = 'Low'
                urgency = 'low'
            
            return {
                'title': title,
                'message': '\n'.join(message_parts),
                'severity': severity,
                'urgency': urgency,
                'category': category,
                'risk_score': risk_score,
                'timestamp': datetime.now(),
                'event_type': event_type,
                'process_name': process_name,
                'rule_triggered': rule_triggered,
                'threat_description': response_data.get('threat_description', ''),
                'raw_event': event_data,
                'raw_response': response_data
            }
            
        except Exception as e:
            self.logger.error(f"Error creating alert data: {e}")
            return {
                'title': '🐧 Linux Security Alert',
                'message': 'Security event detected',
                'severity': 'Medium',
                'urgency': 'normal',
                'category': 'general',
                'risk_score': 50,
                'timestamp': datetime.now()
            }
    
    def _generate_alert_key(self, alert_data: Dict[str, Any]) -> str:
        """Generate unique key for alert deduplication"""
        try:
            key_parts = [
                alert_data.get('event_type', 'Unknown'),
                alert_data.get('process_name', 'Unknown'),
                alert_data.get('rule_triggered', ''),
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
            category = alert_data.get('category', 'general')
            
            if category == 'server_rule':
                self.server_rule_alerts += 1
            elif category == 'risk_based':
                self.risk_based_alerts += 1
            else:
                self.local_rule_alerts += 1
                
        except Exception as e:
            self.logger.debug(f"Error updating alert statistics: {e}")
    
    async def _display_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Display alert using available Linux methods"""
        try:
            success = False
            
            # Try GUI notifications first
            if self.display_available and self.show_on_screen:
                success = await self._show_gui_notification(alert_data)
            
            # Always log to console
            self._show_console_alert(alert_data)
            
            # Play sound if enabled
            if self.play_sound and self.sound_enabled:
                self._play_alert_sound()
            
            # Try system-wide notification if critical
            if alert_data.get('severity') == 'Critical':
                self._show_system_alert(alert_data)
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error displaying Linux alert: {e}")
            return False
    
    async def _show_gui_notification(self, alert_data: Dict[str, Any]) -> bool:
        """Show GUI notification using available methods"""
        try:
            title = alert_data['title']
            message = alert_data['message']
            urgency = alert_data.get('urgency', 'normal')
            
            # Try notify-send first (most common)
            if 'notify-send' in self.notification_methods:
                try:
                    cmd = [
                        'notify-send',
                        '--urgency', urgency,
                        '--expire-time', str(self.alert_duration * 1000),
                        '--icon', 'security-high',
                        title,
                        message
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
                        '--passivepopup', f"{title}\n{message}",
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
                        '--text', f"{title}\n{message}"
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    if result.returncode == 0:
                        return True
                except Exception as e:
                    self.logger.debug(f"zenity failed: {e}")
            
            # Try xmessage as fallback
            if 'xmessage' in self.notification_methods:
                try:
                    cmd = [
                        'xmessage',
                        '-center',
                        '-timeout', str(self.alert_duration),
                        f"{title}\n\n{message}"
                    ]
                    
                    subprocess.Popen(cmd)  # Don't wait for user interaction
                    return True
                except Exception as e:
                    self.logger.debug(f"xmessage failed: {e}")
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error showing GUI notification: {e}")
            return False
    
    def _show_console_alert(self, alert_data: Dict[str, Any]):
        """Show alert in console/terminal"""
        try:
            print("\n" + "=" * 80)
            print(f"🚨 LINUX SECURITY ALERT - {alert_data['severity'].upper()}")
            print("=" * 80)
            print(f"Time: {alert_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Title: {alert_data['title']}")
            print(f"Risk Score: {alert_data['risk_score']}/100")
            print("-" * 80)
            print(alert_data['message'])
            print("=" * 80)
            
            # Also log the alert
            self.logger.warning(f"🚨 {alert_data['title']}")
            self.logger.warning(f"   Risk Score: {alert_data['risk_score']}/100")
            self.logger.warning(f"   Details: {alert_data['message']}")
            
        except Exception as e:
            self.logger.error(f"Error showing console alert: {e}")
    
    def _show_system_alert(self, alert_data: Dict[str, Any]):
        """Show system-wide alert for critical threats"""
        try:
            # Use wall command for system-wide notification
            if 'wall' in self.notification_methods:
                try:
                    message = f"CRITICAL SECURITY ALERT: {alert_data['title']}\n{alert_data['message']}"
                    subprocess.run(['wall', message], input=message, text=True, timeout=5)
                except Exception as e:
                    self.logger.debug(f"wall command failed: {e}")
            
        except Exception as e:
            self.logger.debug(f"Error showing system alert: {e}")
    
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
    
    def acknowledge_alert(self, alert_id: str):
        """Acknowledge an alert"""
        try:
            self.acknowledged_alerts.add(alert_id)
            self.logger.info(f"Linux alert acknowledged: {alert_id}")
        except Exception as e:
            self.logger.error(f"Error acknowledging alert: {e}")
    
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
            'platform': 'linux'
        }
    
    def update_settings(self, settings: Dict[str, Any]):
        """Update notification settings"""
        try:
            self.enabled = settings.get('enabled', self.enabled)
            self.show_server_rules = settings.get('show_server_rules', self.show_server_rules)
            self.show_local_rules = settings.get('show_local_rules', self.show_local_rules)
            self.show_risk_based_alerts = settings.get('show_risk_based_alerts', self.show_risk_based_alerts)
            self.show_on_screen = settings.get('show_on_screen', self.show_on_screen)
            self.play_sound = settings.get('play_sound', self.play_sound)
            self.alert_duration = settings.get('alert_duration', self.alert_duration)
            
            self.logger.info("Linux notification settings updated")
            
        except Exception as e:
            self.logger.error(f"Error updating notification settings: {e}")
    
    def test_notification(self):
        """Test notification system"""
        try:
            test_alert = {
                'title': '🐧 Linux Security System Test',
                'message': 'This is a test notification from the Linux EDR Agent.\nAll notification systems are working correctly.',
                'severity': 'Info',
                'urgency': 'normal',
                'category': 'test',
                'risk_score': 0,
                'timestamp': datetime.now()
            }
            
            asyncio.create_task(self._display_alert(test_alert))
            self.logger.info("Linux notification test triggered")
            
        except Exception as e:
            self.logger.error(f"Error testing notifications: {e}")

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
    return linux_notifier

async def show_linux_alert(event_data, response_data: Dict[str, Any]):
    """Convenience function to show Linux alert"""
    try:
        if linux_notifier and linux_notifier.enabled:
            await linux_notifier.process_threat_response(event_data, response_data)
    except Exception as e:
        logging.getLogger(__name__).error(f"Error showing Linux alert: {e}")

def test_linux_notifications():
    """Test Linux notification system"""
    try:
        if linux_notifier:
            linux_notifier.test_notification()
        else:
            print("Linux notifier not initialized")
    except Exception as e:
        logging.getLogger(__name__).error(f"Error testing Linux notifications: {e}")