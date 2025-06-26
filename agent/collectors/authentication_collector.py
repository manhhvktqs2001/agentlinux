# agent/collectors/authentication_collector.py - Linux Authentication Collector
"""
Linux Authentication Collector - Monitor login events, sudo usage, and authentication logs
Enhanced security monitoring for Linux authentication activities
"""

import asyncio
import logging
import time
import json
import subprocess
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventSeverity

@dataclass
class AuthEvent:
    """Authentication event information"""
    timestamp: datetime
    event_type: str
    user: str
    source_ip: Optional[str] = None
    success: bool = True
    details: Dict[str, Any] = None
    raw_message: str = ""

@dataclass
class LoginSession:
    """Login session information"""
    user: str
    session_id: str
    login_time: datetime
    source_ip: Optional[str] = None
    terminal: Optional[str] = None
    process_id: Optional[int] = None
    logout_time: Optional[datetime] = None
    duration: Optional[float] = None

class LinuxAuthenticationCollector(BaseCollector):
    """Linux Authentication Collector - Monitor authentication events"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "authentication")
        self.logger = logging.getLogger(__name__)
        
        # Authentication monitoring
        self.auth_events = []
        self.active_sessions = {}
        self.failed_attempts = {}
        
        # Security monitoring
        self.security_events = []
        self.brute_force_attempts = {}
        self.suspicious_logins = []
        
        # Log file monitoring
        self.log_files = {
            'auth': '/var/log/auth.log',
            'secure': '/var/log/secure',
            'wtmp': '/var/log/wtmp',
            'btmp': '/var/log/btmp'
        }
        
        # Configuration
        self.monitor_auth_log = True
        self.monitor_wtmp = True
        self.monitor_btmp = True
        self.monitor_sudo = True
        self.security_scanning = True
        
        # Thresholds
        self.failed_attempt_threshold = 5
        self.brute_force_threshold = 10
        self.suspicious_ip_threshold = 3
        
        # Tracking
        self.last_auth_check = 0
        self.last_wtmp_check = 0
        self.last_btmp_check = 0
        
    async def initialize(self):
        """Initialize authentication collector"""
        try:
            self.logger.info("🔐 Initializing Linux Authentication Collector...")
            
            # Check log file availability
            await self._check_log_files()
            
            # Initialize session tracking
            await self._initialize_session_tracking()
            
            # Setup security monitoring
            if self.security_scanning:
                await self._setup_security_monitoring()
            
            # Initialize failed attempt tracking
            await self._initialize_failed_attempt_tracking()
            
            self.logger.info("✅ Authentication Collector initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Authentication Collector initialization failed: {e}")
            raise
    
    async def _check_log_files(self):
        """Check availability of authentication log files"""
        try:
            for log_type, log_path in self.log_files.items():
                if os.path.exists(log_path) and os.access(log_path, os.R_OK):
                    self.logger.info(f"📄 {log_type} log available: {log_path}")
                else:
                    self.logger.warning(f"⚠️ {log_type} log not accessible: {log_path}")
                    
        except Exception as e:
            self.logger.error(f"❌ Log file check failed: {e}")
    
    async def _initialize_session_tracking(self):
        """Initialize session tracking"""
        try:
            # Get current active sessions
            active_sessions = await self._get_active_sessions()
            
            for session in active_sessions:
                self.active_sessions[session.session_id] = session
            
            self.logger.info(f"📊 Tracking {len(self.active_sessions)} active sessions")
            
        except Exception as e:
            self.logger.error(f"❌ Session tracking initialization failed: {e}")
    
    async def _setup_security_monitoring(self):
        """Setup security monitoring"""
        try:
            # Check for recent failed attempts
            failed_attempts = await self._get_recent_failed_attempts()
            
            for attempt in failed_attempts:
                await self._track_failed_attempt(attempt)
            
            # Check for suspicious activities
            suspicious_activities = await self._find_suspicious_activities()
            
            for activity in suspicious_activities:
                await self._report_security_event(
                    event_type="suspicious_authentication_activity",
                    severity=EventSeverity.MEDIUM,
                    details=activity
                )
            
        except Exception as e:
            self.logger.error(f"❌ Security monitoring setup failed: {e}")
    
    async def _initialize_failed_attempt_tracking(self):
        """Initialize failed attempt tracking"""
        try:
            # Initialize tracking for common users
            common_users = ['root', 'admin', 'ubuntu', 'centos', 'debian']
            
            for user in common_users:
                self.failed_attempts[user] = {
                    'count': 0,
                    'last_attempt': None,
                    'source_ips': set(),
                    'attempts': []
                }
            
        except Exception as e:
            self.logger.error(f"❌ Failed attempt tracking initialization failed: {e}")
    
    async def collect_data(self):
        """Collect authentication data"""
        try:
            if not self.is_running:
                return
            
            # Monitor authentication log
            if self.monitor_auth_log:
                await self._monitor_auth_log()
            
            # Monitor wtmp (successful logins)
            if self.monitor_wtmp and time.time() - self.last_wtmp_check > 60:
                await self._monitor_wtmp()
                self.last_wtmp_check = time.time()
            
            # Monitor btmp (failed logins)
            if self.monitor_btmp and time.time() - self.last_btmp_check > 60:
                await self._monitor_btmp()
                self.last_btmp_check = time.time()
            
            # Monitor sudo usage
            if self.monitor_sudo:
                await self._monitor_sudo_usage()
            
            # Security scanning
            if self.security_scanning:
                await self._perform_security_scan()
            
        except Exception as e:
            self.logger.error(f"❌ Authentication data collection failed: {e}")
    
    async def _monitor_auth_log(self):
        """Monitor authentication log file"""
        try:
            auth_log_path = self.log_files['auth']
            if not os.path.exists(auth_log_path):
                return
            
            # Get recent log entries
            result = subprocess.run(
                ['tail', '-n', '50', auth_log_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        auth_event = self._parse_auth_log_line(line)
                        if auth_event:
                            await self._handle_auth_event(auth_event)
            
        except Exception as e:
            self.logger.error(f"❌ Auth log monitoring failed: {e}")
    
    def _parse_auth_log_line(self, line: str) -> Optional[AuthEvent]:
        """Parse authentication log line"""
        try:
            # Common auth log format: timestamp hostname service: message
            parts = line.split()
            if len(parts) < 4:
                return None
            
            # Extract timestamp
            timestamp_str = f"{parts[0]} {parts[1]} {parts[2]}"
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=datetime.now().year)
            
            # Extract service and message
            service_part = parts[3].rstrip(':')
            message = ' '.join(parts[4:])
            
            # Parse different types of auth events
            if 'sshd' in service_part:
                return self._parse_sshd_event(timestamp, message)
            elif 'sudo' in service_part:
                return self._parse_sudo_event(timestamp, message)
            elif 'login' in service_part:
                return self._parse_login_event(timestamp, message)
            elif 'su' in service_part:
                return self._parse_su_event(timestamp, message)
            
        except Exception as e:
            self.logger.debug(f"Failed to parse auth log line: {e}")
        
        return None
    
    def _parse_sshd_event(self, timestamp: datetime, message: str) -> Optional[AuthEvent]:
        """Parse SSH authentication event"""
        try:
            # Successful login
            if 'Accepted password' in message or 'Accepted publickey' in message:
                match = re.search(r'Accepted \w+ for (\w+) from ([\d.]+)', message)
                if match:
                    user = match.group(1)
                    source_ip = match.group(2)
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='ssh_login_success',
                        user=user,
                        source_ip=source_ip,
                        success=True,
                        details={'method': 'password' if 'password' in message else 'publickey'},
                        raw_message=message
                    )
            
            # Failed login
            elif 'Failed password' in message or 'Invalid user' in message:
                match = re.search(r'(?:Failed password|Invalid user) (?:for )?(\w+) from ([\d.]+)', message)
                if match:
                    user = match.group(1)
                    source_ip = match.group(2)
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='ssh_login_failed',
                        user=user,
                        source_ip=source_ip,
                        success=False,
                        details={'reason': 'invalid_credentials'},
                        raw_message=message
                    )
            
            # Connection closed
            elif 'Connection closed' in message:
                match = re.search(r'Connection closed by ([\d.]+)', message)
                if match:
                    source_ip = match.group(1)
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='ssh_connection_closed',
                        user='unknown',
                        source_ip=source_ip,
                        success=True,
                        details={'reason': 'connection_closed'},
                        raw_message=message
                    )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse SSH event: {e}")
        
        return None
    
    def _parse_sudo_event(self, timestamp: datetime, message: str) -> Optional[AuthEvent]:
        """Parse sudo event"""
        try:
            # Successful sudo
            if 'session opened' in message:
                match = re.search(r'(\w+) : TTY=(\w+) ; PWD=([^;]+) ; USER=(\w+) ; COMMAND=(.+)', message)
                if match:
                    user = match.group(1)
                    tty = match.group(2)
                    pwd = match.group(3)
                    target_user = match.group(4)
                    command = match.group(5)
                    
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='sudo_success',
                        user=user,
                        success=True,
                        details={
                            'target_user': target_user,
                            'command': command,
                            'tty': tty,
                            'pwd': pwd
                        },
                        raw_message=message
                    )
            
            # Failed sudo
            elif 'incorrect password' in message or 'authentication failure' in message:
                match = re.search(r'(\w+) : (\w+) ; TTY=(\w+) ; PWD=([^;]+) ; USER=(\w+) ; COMMAND=(.+)', message)
                if match:
                    user = match.group(1)
                    target_user = match.group(5)
                    command = match.group(6)
                    
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='sudo_failed',
                        user=user,
                        success=False,
                        details={
                            'target_user': target_user,
                            'command': command,
                            'reason': 'incorrect_password'
                        },
                        raw_message=message
                    )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse sudo event: {e}")
        
        return None
    
    def _parse_login_event(self, timestamp: datetime, message: str) -> Optional[AuthEvent]:
        """Parse login event"""
        try:
            # Successful login
            if 'LOGIN' in message:
                match = re.search(r'LOGIN on (\w+) by (\w+)', message)
                if match:
                    tty = match.group(1)
                    user = match.group(2)
                    
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='login_success',
                        user=user,
                        success=True,
                        details={'tty': tty},
                        raw_message=message
                    )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse login event: {e}")
        
        return None
    
    def _parse_su_event(self, timestamp: datetime, message: str) -> Optional[AuthEvent]:
        """Parse su event"""
        try:
            # Successful su
            if 'session opened' in message:
                match = re.search(r'(\w+) to (\w+) on (\w+)', message)
                if match:
                    from_user = match.group(1)
                    to_user = match.group(2)
                    tty = match.group(3)
                    
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='su_success',
                        user=from_user,
                        success=True,
                        details={
                            'target_user': to_user,
                            'tty': tty
                        },
                        raw_message=message
                    )
            
            # Failed su
            elif 'FAILED su' in message:
                match = re.search(r'(\w+) to (\w+) on (\w+)', message)
                if match:
                    from_user = match.group(1)
                    to_user = match.group(2)
                    tty = match.group(3)
                    
                    return AuthEvent(
                        timestamp=timestamp,
                        event_type='su_failed',
                        user=from_user,
                        success=False,
                        details={
                            'target_user': to_user,
                            'tty': tty,
                            'reason': 'incorrect_password'
                        },
                        raw_message=message
                    )
            
        except Exception as e:
            self.logger.debug(f"Failed to parse su event: {e}")
        
        return None
    
    async def _handle_auth_event(self, auth_event: AuthEvent):
        """Handle authentication event"""
        try:
            # Add to events list
            self.auth_events.append(auth_event)
            
            # Create event data
            event_data = EventData(
                event_type=EventType.AUTHENTICATION,
                severity=EventSeverity.INFO if auth_event.success else EventSeverity.MEDIUM,
                source="authentication_collector",
                data={
                    'auth_event_type': auth_event.event_type,
                    'user': auth_event.user,
                    'source_ip': auth_event.source_ip,
                    'success': auth_event.success,
                    'timestamp': auth_event.timestamp.isoformat(),
                    'details': auth_event.details
                }
            )
            
            await self._send_event(event_data)
            
            # Track failed attempts
            if not auth_event.success:
                await self._track_failed_attempt(auth_event)
            
            # Handle successful logins
            if auth_event.success and 'login' in auth_event.event_type:
                await self._handle_successful_login(auth_event)
            
            # Handle logouts
            if 'logout' in auth_event.event_type or 'connection_closed' in auth_event.event_type:
                await self._handle_logout(auth_event)
            
        except Exception as e:
            self.logger.error(f"❌ Auth event handling failed: {e}")
    
    async def _track_failed_attempt(self, auth_event: AuthEvent):
        """Track failed authentication attempts"""
        try:
            user = auth_event.user
            source_ip = auth_event.source_ip
            
            if user not in self.failed_attempts:
                self.failed_attempts[user] = {
                    'count': 0,
                    'last_attempt': None,
                    'source_ips': set(),
                    'attempts': []
                }
            
            # Update tracking
            self.failed_attempts[user]['count'] += 1
            self.failed_attempts[user]['last_attempt'] = auth_event.timestamp
            if source_ip:
                self.failed_attempts[user]['source_ips'].add(source_ip)
            
            self.failed_attempts[user]['attempts'].append({
                'timestamp': auth_event.timestamp,
                'source_ip': source_ip,
                'event_type': auth_event.event_type
            })
            
            # Check for brute force attempts
            if self.failed_attempts[user]['count'] >= self.brute_force_threshold:
                await self._report_security_event(
                    event_type="brute_force_attempt",
                    severity=EventSeverity.HIGH,
                    details={
                        'user': user,
                        'attempt_count': self.failed_attempts[user]['count'],
                        'source_ips': list(self.failed_attempts[user]['source_ips']),
                        'last_attempt': auth_event.timestamp.isoformat()
                    }
                )
            
            # Check for suspicious activity
            if len(self.failed_attempts[user]['source_ips']) >= self.suspicious_ip_threshold:
                await self._report_security_event(
                    event_type="multiple_source_ips",
                    severity=EventSeverity.MEDIUM,
                    details={
                        'user': user,
                        'source_ips': list(self.failed_attempts[user]['source_ips']),
                        'attempt_count': self.failed_attempts[user]['count']
                    }
                )
            
        except Exception as e:
            self.logger.error(f"❌ Failed attempt tracking failed: {e}")
    
    async def _handle_successful_login(self, auth_event: AuthEvent):
        """Handle successful login"""
        try:
            session_id = f"{auth_event.user}_{auth_event.timestamp.strftime('%Y%m%d_%H%M%S')}"
            
            session = LoginSession(
                user=auth_event.user,
                session_id=session_id,
                login_time=auth_event.timestamp,
                source_ip=auth_event.source_ip,
                terminal=auth_event.details.get('tty') if auth_event.details else None
            )
            
            self.active_sessions[session_id] = session
            
            self.logger.info(f"🔓 User {auth_event.user} logged in from {auth_event.source_ip}")
            
        except Exception as e:
            self.logger.error(f"❌ Successful login handling failed: {e}")
    
    async def _handle_logout(self, auth_event: AuthEvent):
        """Handle logout"""
        try:
            # Find matching session
            for session_id, session in list(self.active_sessions.items()):
                if (session.user == auth_event.user and 
                    session.source_ip == auth_event.source_ip):
                    
                    # Update session
                    session.logout_time = auth_event.timestamp
                    session.duration = (session.logout_time - session.login_time).total_seconds()
                    
                    # Remove from active sessions
                    del self.active_sessions[session_id]
                    
                    self.logger.info(f"🔒 User {auth_event.user} logged out (session duration: {session.duration:.1f}s)")
                    break
            
        except Exception as e:
            self.logger.error(f"❌ Logout handling failed: {e}")
    
    async def _monitor_wtmp(self):
        """Monitor wtmp file for successful logins"""
        try:
            wtmp_path = self.log_files['wtmp']
            if not os.path.exists(wtmp_path):
                return
            
            # Get recent wtmp entries
            result = subprocess.run(
                ['last', '-n', '20'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and not line.startswith('wtmp'):
                        login_info = self._parse_last_output(line)
                        if login_info:
                            await self._handle_wtmp_login(login_info)
            
        except Exception as e:
            self.logger.error(f"❌ wtmp monitoring failed: {e}")
    
    def _parse_last_output(self, line: str) -> Optional[Dict]:
        """Parse last command output"""
        try:
            parts = line.split()
            if len(parts) >= 4:
                user = parts[0]
                tty = parts[1]
                source = parts[2]
                login_time = ' '.join(parts[3:])
                
                return {
                    'user': user,
                    'tty': tty,
                    'source': source,
                    'login_time': login_time
                }
        
        except Exception as e:
            self.logger.debug(f"Failed to parse last output: {e}")
        
        return None
    
    async def _handle_wtmp_login(self, login_info: Dict):
        """Handle wtmp login information"""
        try:
            # Create event for successful login
            event_data = EventData(
                event_type=EventType.AUTHENTICATION,
                severity=EventSeverity.INFO,
                source="authentication_collector",
                data={
                    'auth_event_type': 'wtmp_login',
                    'user': login_info['user'],
                    'tty': login_info['tty'],
                    'source': login_info['source'],
                    'login_time': login_info['login_time']
                }
            )
            
            await self._send_event(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ wtmp login handling failed: {e}")
    
    async def _monitor_btmp(self):
        """Monitor btmp file for failed logins"""
        try:
            btmp_path = self.log_files['btmp']
            if not os.path.exists(btmp_path):
                return
            
            # Get recent btmp entries
            result = subprocess.run(
                ['lastb', '-n', '20'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip() and not line.startswith('btmp'):
                        failed_info = self._parse_lastb_output(line)
                        if failed_info:
                            await self._handle_btmp_failed(failed_info)
            
        except Exception as e:
            self.logger.error(f"❌ btmp monitoring failed: {e}")
    
    def _parse_lastb_output(self, line: str) -> Optional[Dict]:
        """Parse lastb command output"""
        try:
            parts = line.split()
            if len(parts) >= 4:
                user = parts[0]
                tty = parts[1]
                source = parts[2]
                attempt_time = ' '.join(parts[3:])
                
                return {
                    'user': user,
                    'tty': tty,
                    'source': source,
                    'attempt_time': attempt_time
                }
        
        except Exception as e:
            self.logger.debug(f"Failed to parse lastb output: {e}")
        
        return None
    
    async def _handle_btmp_failed(self, failed_info: Dict):
        """Handle btmp failed login information"""
        try:
            # Create event for failed login
            event_data = EventData(
                event_type=EventType.AUTHENTICATION,
                severity=EventSeverity.MEDIUM,
                source="authentication_collector",
                data={
                    'auth_event_type': 'btmp_failed',
                    'user': failed_info['user'],
                    'tty': failed_info['tty'],
                    'source': failed_info['source'],
                    'attempt_time': failed_info['attempt_time']
                }
            )
            
            await self._send_event(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ btmp failed login handling failed: {e}")
    
    async def _monitor_sudo_usage(self):
        """Monitor sudo usage"""
        try:
            # Check for recent sudo usage in auth log
            auth_log_path = self.log_files['auth']
            if os.path.exists(auth_log_path):
                result = subprocess.run(
                    ['grep', 'sudo', auth_log_path, '|', 'tail', '-n', '10'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            auth_event = self._parse_auth_log_line(line)
                            if auth_event and 'sudo' in auth_event.event_type:
                                await self._handle_auth_event(auth_event)
            
        except Exception as e:
            self.logger.error(f"❌ sudo monitoring failed: {e}")
    
    async def _perform_security_scan(self):
        """Perform security scanning"""
        try:
            # Check for brute force attempts
            for user, attempts in self.failed_attempts.items():
                if attempts['count'] >= self.brute_force_threshold:
                    await self._report_security_event(
                        event_type="brute_force_detected",
                        severity=EventSeverity.HIGH,
                        details={
                            'user': user,
                            'attempt_count': attempts['count'],
                            'source_ips': list(attempts['source_ips']),
                            'last_attempt': attempts['last_attempt'].isoformat() if attempts['last_attempt'] else None
                        }
                    )
            
            # Check for suspicious activities
            suspicious_activities = await self._find_suspicious_activities()
            
            for activity in suspicious_activities:
                await self._report_security_event(
                    event_type="suspicious_authentication_activity",
                    severity=EventSeverity.MEDIUM,
                    details=activity
                )
        
        except Exception as e:
            self.logger.error(f"❌ Security scanning failed: {e}")
    
    async def _find_suspicious_activities(self) -> List[Dict]:
        """Find suspicious authentication activities"""
        activities = []
        
        try:
            # Check for root login attempts
            if 'root' in self.failed_attempts and self.failed_attempts['root']['count'] > 0:
                activities.append({
                    'type': 'root_login_attempts',
                    'attempt_count': self.failed_attempts['root']['count'],
                    'source_ips': list(self.failed_attempts['root']['source_ips'])
                })
            
            # Check for multiple failed users
            failed_users = [user for user, data in self.failed_attempts.items() if data['count'] > 0]
            if len(failed_users) > 3:
                activities.append({
                    'type': 'multiple_failed_users',
                    'failed_users': failed_users,
                    'total_attempts': sum(data['count'] for data in self.failed_attempts.values())
                })
            
            # Check for unusual login times
            current_hour = datetime.now().hour
            if current_hour < 6 or current_hour > 22:  # Late night/early morning
                for session in self.active_sessions.values():
                    if session.login_time.hour < 6 or session.login_time.hour > 22:
                        activities.append({
                            'type': 'unusual_login_time',
                            'user': session.user,
                            'login_time': session.login_time.isoformat(),
                            'source_ip': session.source_ip
                        })
        
        except Exception as e:
            self.logger.error(f"❌ Suspicious activity search failed: {e}")
        
        return activities
    
    async def _get_active_sessions(self) -> List[LoginSession]:
        """Get currently active sessions"""
        sessions = []
        
        try:
            # Get current logged in users
            result = subprocess.run(
                ['who'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        session_info = self._parse_who_output(line)
                        if session_info:
                            sessions.append(session_info)
        
        except Exception as e:
            self.logger.error(f"❌ Active session detection failed: {e}")
        
        return sessions
    
    def _parse_who_output(self, line: str) -> Optional[LoginSession]:
        """Parse who command output"""
        try:
            parts = line.split()
            if len(parts) >= 3:
                user = parts[0]
                tty = parts[1]
                login_time_str = ' '.join(parts[2:])
                
                # Parse login time
                try:
                    login_time = datetime.strptime(login_time_str, "%Y-%m-%d %H:%M")
                except:
                    login_time = datetime.now()
                
                session_id = f"{user}_{login_time.strftime('%Y%m%d_%H%M%S')}"
                
                return LoginSession(
                    user=user,
                    session_id=session_id,
                    login_time=login_time,
                    terminal=tty
                )
        
        except Exception as e:
            self.logger.debug(f"Failed to parse who output: {e}")
        
        return None
    
    async def _get_recent_failed_attempts(self) -> List[AuthEvent]:
        """Get recent failed authentication attempts"""
        attempts = []
        
        try:
            # Check auth log for recent failed attempts
            auth_log_path = self.log_files['auth']
            if os.path.exists(auth_log_path):
                result = subprocess.run(
                    ['grep', '-E', '(Failed password|Invalid user)', auth_log_path, '|', 'tail', '-n', '20'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            auth_event = self._parse_auth_log_line(line)
                            if auth_event and not auth_event.success:
                                attempts.append(auth_event)
        
        except Exception as e:
            self.logger.error(f"❌ Recent failed attempts detection failed: {e}")
        
        return attempts
    
    async def _report_security_event(self, event_type: str, severity: EventSeverity, details: Dict):
        """Report security event"""
        try:
            event_data = EventData(
                event_type=EventType.AUTHENTICATION_SECURITY,
                severity=severity,
                source="authentication_collector",
                data={
                    'security_event_type': event_type,
                    'details': details
                }
            )
            
            await self._send_event(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ Security event reporting failed: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            'collector_type': 'authentication',
            'is_running': self.is_running,
            'auth_events': len(self.auth_events),
            'active_sessions': len(self.active_sessions),
            'failed_attempts': len([u for u, d in self.failed_attempts.items() if d['count'] > 0]),
            'security_events': len(self.security_events),
            'brute_force_attempts': len(self.brute_force_attempts),
            'suspicious_logins': len(self.suspicious_logins)
        }
