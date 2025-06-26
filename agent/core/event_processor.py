# agent/core/event_processor.py - ENHANCED LINUX EVENT PROCESSOR
"""
Enhanced Linux Event Processor - IMPROVED DATABASE COMPATIBILITY
Optimized for Linux systems with complete database schema compliance
"""

import asyncio
import logging
import time
import threading
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import deque
from dataclasses import dataclass
import uuid
from pathlib import Path

from agent.core.config_manager import ConfigManager
from agent.core.communication import ServerCommunication
from agent.schemas.events import EventData
from agent.utils.security_notifications import LinuxSecurityNotifier

@dataclass
class EventStats:
    """Enhanced event processing statistics for Linux"""
    events_collected: int = 0
    events_sent: int = 0
    events_failed: int = 0
    rule_violations_received: int = 0
    rule_alerts_displayed: int = 0
    local_rules_triggered: int = 0
    server_rules_triggered: int = 0
    critical_events: int = 0
    high_events: int = 0
    medium_events: int = 0
    low_events: int = 0
    info_events: int = 0
    last_event_sent: Optional[datetime] = None
    last_rule_violation: Optional[datetime] = None
    processing_rate: float = 0.0
    database_errors: int = 0
    schema_validation_errors: int = 0

class EnhancedLinuxEventProcessor:
    """Enhanced Linux Event Processor with improved database compatibility"""
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Thread-safe logging
        self._log_lock = threading.Lock()
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.agent_config = self.config.get('agent', {})
        
        # Enhanced Linux processing settings
        self.immediate_send = True
        self.batch_size = 1
        self.batch_interval = 0.001
        self.max_queue_size = 2000
        
        # Processing state
        self.is_running = False
        self.agent_id: Optional[str] = None
        
        # Enhanced statistics
        self.stats = EventStats()
        
        # Processing tracking
        self.processing_start_time = time.time()
        
        # Enhanced Linux security notifications
        self.security_notifier = self._initialize_enhanced_notifier()
        
        # Enhanced event queue with priority support
        self._critical_events_queue = deque(maxlen=500)
        self._high_events_queue = deque(maxlen=800) 
        self._normal_events_queue = deque(maxlen=1500)
        self._failed_events_queue = deque(maxlen=1000)
        
        # Enhanced retry mechanism
        self._retry_task = None
        self._priority_send_task = None
        
        # Processing locks
        self._processing_lock = asyncio.Lock()
        self._send_errors = 0
        self._consecutive_failures = 0
        self._last_successful_send = time.time()
        
        # Database compatibility tracking
        self._database_validation_enabled = True
        self._schema_validation_cache = {}
        
        # Enhanced rule processing
        self.rule_processing_enabled = True
        self.local_rule_processing = True
        self.server_rule_processing = True
        
        # Linux-specific optimizations
        self.linux_platform = True
        self.enhanced_monitoring = True
        self.real_time_processing = True
        
        # Performance metrics
        self._event_processing_times = deque(maxlen=100)
        self._database_response_times = deque(maxlen=100)
        
        self._safe_log("info", "🐧 ENHANCED Linux Event Processor initialized - IMPROVED DATABASE COMPATIBILITY")
        self._safe_log("info", f"   📊 Queue Sizes - Critical: 500, High: 800, Normal: 1500")
        self._safe_log("info", f"   🔒 Security Features - Notifications: {self.security_notifier is not None}")
        self._safe_log("info", f"   ✅ Database Validation: {self._database_validation_enabled}")
    
    def _initialize_enhanced_notifier(self):
        """Initialize enhanced Linux-specific security notifier"""
        try:
            from agent.utils.security_notifications import initialize_linux_notifier
            notifier = initialize_linux_notifier(self.config_manager)
            if notifier and self.communication:
                notifier.set_communication(self.communication)
                self._safe_log("info", "✅ Enhanced Linux Security Notifier initialized")
                return notifier
            else:
                self._safe_log("warning", "⚠️ Enhanced Linux Security Notifier initialization failed")
                return None
        except Exception as e:
            self._safe_log("error", f"❌ Error initializing enhanced Linux notifier: {e}")
            return None
    
    def _safe_log(self, level: str, message: str):
        """Enhanced thread-safe logging for Linux"""
        try:
            with self._log_lock:
                linux_message = f"🐧 ENHANCED {message}"
                getattr(self.logger, level)(linux_message)
        except:
            pass
    
    async def start(self):
        """Start enhanced Linux event processor"""
        try:
            self.is_running = True
            self.processing_start_time = time.time()
            self._safe_log("info", "🚀 ENHANCED Linux Event Processor started - IMPROVED DATABASE PROCESSING")
            
            # Start enhanced retry mechanism
            self._retry_task = asyncio.create_task(self._enhanced_retry_loop())
            
            # Start priority processing task
            self._priority_send_task = asyncio.create_task(self._priority_processing_loop())
            
            # Start enhanced statistics logging
            asyncio.create_task(self._enhanced_stats_logging_loop())
            
            # Start Linux performance monitoring
            asyncio.create_task(self._linux_performance_monitor())
            
            # Start database health monitoring
            asyncio.create_task(self._database_health_monitor())
            
        except Exception as e:
            self._safe_log("error", f"Enhanced Linux event processor start error: {e}")
            raise
    
    async def stop(self):
        """Stop enhanced Linux event processor gracefully"""
        try:
            self._safe_log("info", "🛑 Stopping ENHANCED Linux Event Processor...")
            self.is_running = False
            
            # Cancel tasks
            if self._retry_task:
                self._retry_task.cancel()
            if self._priority_send_task:
                self._priority_send_task.cancel()
            
            # Flush all queues
            await self._flush_all_queues()
            
            await asyncio.sleep(0.5)
            
            # Final statistics
            await self._log_final_statistics()
            
            self._safe_log("info", "✅ ENHANCED Linux Event Processor stopped gracefully")
            
        except Exception as e:
            self._safe_log("error", f"❌ Enhanced Linux event processor stop error: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for enhanced Linux communication"""
        self.agent_id = agent_id
        self._safe_log("info", f"Enhanced Agent ID set for Linux: {agent_id}")
    
    async def add_event(self, event_data: EventData):
        """
        ENHANCED: Add event with priority queuing and improved database validation
        """
        try:
            start_time = time.time()
            
            # ENHANCED: Ensure agent_id and validate
            if self.agent_id and not event_data.agent_id:
                event_data.agent_id = self.agent_id
            
            if not event_data.agent_id:
                self.stats.events_failed += 1
                self.stats.schema_validation_errors += 1
                self._safe_log("error", "❌ Event missing agent_id - DATABASE VALIDATION FAILED")
                return
            
            # ENHANCED: Add Linux platform identifier
            if not event_data.raw_event_data:
                event_data.raw_event_data = {}
            event_data.raw_event_data['platform'] = 'linux'
            event_data.raw_event_data['processor_version'] = 'enhanced_v2.1'
            event_data.raw_event_data['database_compatible'] = True
            
            # ENHANCED: Database schema validation
            if self._database_validation_enabled:
                validation_result = await self._validate_event_schema(event_data)
                if not validation_result['valid']:
                    self.stats.schema_validation_errors += 1
                    self._safe_log("error", f"❌ Event schema validation failed: {validation_result['error']}")
                    return
            
            # ENHANCED: Update stats by severity
            self._update_severity_stats(event_data.severity)
            self.stats.events_collected += 1
            
            # ENHANCED: Priority-based queuing
            priority = self._determine_event_priority(event_data)
            queue_success = self._add_to_priority_queue(event_data, priority)
            
            if not queue_success:
                self.stats.events_failed += 1
                self._safe_log("warning", f"⚠️ Event queue full - {priority} priority")
                return
            
            # ENHANCED: Immediate processing for critical events
            if priority == 'critical' and self.agent_id and self.communication:
                await self._process_critical_event_immediately(event_data)
            
            # Record processing time
            processing_time = time.time() - start_time
            self._event_processing_times.append(processing_time)
            
        except Exception as e:
            self.stats.events_failed += 1
            self._safe_log("error", f"❌ Enhanced Linux event processing error: {e}")
    
    async def _validate_event_schema(self, event_data: EventData) -> Dict[str, Any]:
        """Enhanced database schema validation"""
        try:
            # Create cache key
            cache_key = f"{event_data.event_type}_{event_data.event_action}"
            
            # Check cache first
            if cache_key in self._schema_validation_cache:
                cached_result = self._schema_validation_cache[cache_key]
                if cached_result['timestamp'] > time.time() - 300:  # 5 minutes cache
                    return cached_result['result']
            
            # Perform validation
            validation_errors = []
            
            # Required fields validation
            required_fields = ['agent_id', 'event_type', 'event_action', 'event_timestamp', 'severity']
            for field in required_fields:
                if not getattr(event_data, field, None):
                    validation_errors.append(f"Missing required field: {field}")
            
            # Field length validation (database constraints)
            if event_data.process_name and len(event_data.process_name) > 255:
                validation_errors.append("ProcessName exceeds 255 characters")
            
            if event_data.file_path and len(event_data.file_path) > 500:
                validation_errors.append("FilePath exceeds 500 characters")
            
            if event_data.command_line and len(event_data.command_line) > 2000:
                validation_errors.append("CommandLine exceeds 2000 characters")
            
            # Data type validation
            if event_data.risk_score and not (0 <= event_data.risk_score <= 100):
                validation_errors.append("RiskScore must be between 0 and 100")
            
            if event_data.source_port and not (0 <= event_data.source_port <= 65535):
                validation_errors.append("SourcePort must be between 0 and 65535")
            
            if event_data.destination_port and not (0 <= event_data.destination_port <= 65535):
                validation_errors.append("DestinationPort must be between 0 and 65535")
            
            # Severity validation
            valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
            if event_data.severity not in valid_severities:
                validation_errors.append(f"Invalid severity: {event_data.severity}")
            
            # Event type validation
            valid_event_types = ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System']
            if event_data.event_type not in valid_event_types:
                validation_errors.append(f"Invalid event_type: {event_data.event_type}")
            
            # Threat level validation
            valid_threat_levels = ['None', 'Suspicious', 'Malicious']
            if event_data.threat_level not in valid_threat_levels:
                validation_errors.append(f"Invalid threat_level: {event_data.threat_level}")
            
            # Create result
            result = {
                'valid': len(validation_errors) == 0,
                'error': '; '.join(validation_errors) if validation_errors else None,
                'errors': validation_errors
            }
            
            # Cache result
            self._schema_validation_cache[cache_key] = {
                'result': result,
                'timestamp': time.time()
            }
            
            return result
            
        except Exception as e:
            return {
                'valid': False,
                'error': f"Validation exception: {str(e)}",
                'errors': [str(e)]
            }
    
    def _determine_event_priority(self, event_data: EventData) -> str:
        """Determine event priority for queue management"""
        try:
            severity = event_data.severity.lower()
            risk_score = event_data.risk_score or 0
            
            # Critical priority
            if (severity == 'critical' or 
                risk_score >= 90 or 
                event_data.threat_level == 'Malicious'):
                return 'critical'
            
            # High priority  
            if (severity == 'high' or 
                risk_score >= 70 or 
                event_data.threat_level == 'Suspicious'):
                return 'high'
            
            # Normal priority for everything else
            return 'normal'
            
        except Exception:
            return 'normal'
    
    def _add_to_priority_queue(self, event_data: EventData, priority: str) -> bool:
        """Add event to appropriate priority queue"""
        try:
            if priority == 'critical':
                if len(self._critical_events_queue) < 500:
                    self._critical_events_queue.append({
                        'event': event_data,
                        'timestamp': time.time(),
                        'retry_count': 0,
                        'priority': priority
                    })
                    return True
            elif priority == 'high':
                if len(self._high_events_queue) < 800:
                    self._high_events_queue.append({
                        'event': event_data,
                        'timestamp': time.time(),
                        'retry_count': 0,
                        'priority': priority
                    })
                    return True
            else:  # normal
                if len(self._normal_events_queue) < 1500:
                    self._normal_events_queue.append({
                        'event': event_data,
                        'timestamp': time.time(),
                        'retry_count': 0,
                        'priority': priority
                    })
                    return True
            
            return False
            
        except Exception as e:
            self._safe_log("error", f"❌ Error adding to priority queue: {e}")
            return False
    
    async def _process_critical_event_immediately(self, event_data: EventData):
        """Process critical events immediately"""
        try:
            if not self.communication or not self.communication.is_connected():
                return
            
            success, response, error = await self.communication.submit_event(event_data)
            
            if success and response:
                await self._process_enhanced_server_response(response, event_data)
                self.stats.events_sent += 1
                self.stats.last_event_sent = datetime.now()
                self._safe_log("info", f"🚨 CRITICAL event processed immediately - {event_data.event_type}")
            else:
                # Add to failed queue for retry
                self._failed_events_queue.append({
                    'event': event_data,
                    'timestamp': time.time(),
                    'retry_count': 0,
                    'priority': 'critical'
                })
                self.stats.events_failed += 1
                
        except Exception as e:
            self._safe_log("error", f"❌ Critical event immediate processing failed: {e}")
    
    async def _priority_processing_loop(self):
        """Enhanced priority-based event processing loop"""
        try:
            while self.is_running:
                try:
                    events_processed = 0
                    
                    # Process critical events first (higher frequency)
                    events_processed += await self._process_queue(self._critical_events_queue, 'critical', max_events=10)
                    
                    # Process high priority events
                    events_processed += await self._process_queue(self._high_events_queue, 'high', max_events=5)
                    
                    # Process normal events
                    events_processed += await self._process_queue(self._normal_events_queue, 'normal', max_events=3)
                    
                    # Adaptive sleep based on activity
                    if events_processed > 0:
                        await asyncio.sleep(0.1)  # Fast processing when active
                    else:
                        await asyncio.sleep(0.5)  # Slower when idle
                        
                except Exception as e:
                    self._safe_log("error", f"❌ Priority processing loop error: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            self._safe_log("error", f"❌ Priority processing loop failed: {e}")
    
    async def _process_queue(self, queue: deque, priority: str, max_events: int = 5) -> int:
        """Process events from a priority queue"""
        processed = 0
        
        try:
            while queue and processed < max_events:
                if not self.communication or not self.communication.is_connected():
                    break
                
                event_info = queue.popleft()
                event_data = event_info['event']
                
                success, response, error = await self.communication.submit_event(event_data)
                
                if success and response:
                    await self._process_enhanced_server_response(response, event_data)
                    self.stats.events_sent += 1
                    self.stats.last_event_sent = datetime.now()
                    processed += 1
                    self._consecutive_failures = 0
                    self._last_successful_send = time.time()
                else:
                    # Add to failed queue for retry
                    event_info['retry_count'] += 1
                    if event_info['retry_count'] <= 3:
                        self._failed_events_queue.append(event_info)
                    self.stats.events_failed += 1
                    self._consecutive_failures += 1
                    
        except Exception as e:
            self._safe_log("error", f"❌ Error processing {priority} queue: {e}")
        
        return processed
    
    async def _process_enhanced_server_response(self, server_response: Dict[str, Any], original_event: EventData):
        """Enhanced server response processing with improved rule detection"""
        try:
            if not server_response:
                return
            
            rule_violation_detected = False
            alerts_to_display = []
            
            # ENHANCED: Process ALL types of rule violations and alerts
            
            # CASE 1: Server returned alerts_generated (array of alerts)
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                alerts = server_response['alerts_generated']
                
                for alert in alerts:
                    if self._is_valid_linux_alert(alert):
                        alert['platform'] = 'linux'
                        alert['desktop_environment'] = self._get_desktop_environment()
                        alert['database_compatible'] = True
                        alerts_to_display.append(alert)
                        rule_violation_detected = True
                
                if alerts_to_display:
                    self.stats.rule_violations_received += len(alerts_to_display)
                    
                    # Enhanced local vs server rule tracking
                    if server_response.get('local_rule_triggered'):
                        self.stats.local_rules_triggered += len(alerts_to_display)
                        self._safe_log("warning", f"🔍 ENHANCED LOCAL RULE: {len(alerts_to_display)} alerts")
                    else:
                        self.stats.server_rules_triggered += len(alerts_to_display)
                        self._safe_log("warning", f"🚨 ENHANCED SERVER RULE: {len(alerts_to_display)} alerts")
            
            # CASE 2: Single rule_triggered with threat_detected
            elif (server_response.get('threat_detected', False) and 
                  server_response.get('rule_triggered')):
                
                enhanced_alert = {
                    'id': f'enhanced_linux_rule_{int(time.time())}_{uuid.uuid4().hex[:8]}',
                    'alert_id': f'enhanced_linux_rule_{int(time.time())}',
                    'rule_id': server_response.get('rule_id', 'UNKNOWN_RULE'),
                    'rule_name': server_response.get('rule_name', server_response.get('rule_triggered')),
                    'rule_description': server_response.get('rule_description', ''),
                    'title': f'🐧 Enhanced Linux Rule: {server_response.get("rule_triggered")}',
                    'description': server_response.get('threat_description', 'Enhanced Linux rule violation detected'),
                    'severity': self._map_risk_to_severity(server_response.get('risk_score', 50)),
                    'risk_score': server_response.get('risk_score', 50),
                    'detection_method': server_response.get('detection_method', 'Enhanced Linux Rule Engine'),
                    'mitre_technique': server_response.get('mitre_technique'),
                    'mitre_tactic': server_response.get('mitre_tactic'),
                    'event_id': server_response.get('event_id'),
                    'timestamp': datetime.now().isoformat(),
                    'server_generated': True,
                    'rule_violation': True,
                    'platform': 'linux',
                    'desktop_environment': self._get_desktop_environment(),
                    'database_compatible': True,
                    'enhanced_processing': True,
                    'process_name': original_event.process_name,
                    'process_path': original_event.process_path,
                    'file_path': original_event.file_path,
                    'local_rule': server_response.get('local_rule_triggered', False)
                }
                
                alerts_to_display.append(enhanced_alert)
                rule_violation_detected = True
                self.stats.rule_violations_received += 1
                
                if server_response.get('local_rule_triggered'):
                    self.stats.local_rules_triggered += 1
                else:
                    self.stats.server_rules_triggered += 1
            
            # CASE 3: High risk score detection
            elif server_response.get('risk_score', 0) >= 70:
                risk_alert = {
                    'id': f'enhanced_linux_risk_{int(time.time())}_{uuid.uuid4().hex[:8]}',
                    'alert_id': f'enhanced_linux_risk_{int(time.time())}',
                    'rule_id': 'ENHANCED_LINUX_HIGH_RISK',
                    'rule_name': 'Enhanced Linux High Risk Score Detection',
                    'title': f'🐧 Enhanced Linux High Risk Activity',
                    'description': f'High risk Linux {original_event.event_type} activity (Score: {server_response.get("risk_score")})',
                    'severity': 'HIGH',
                    'risk_score': server_response.get('risk_score'),
                    'detection_method': 'Enhanced Linux Risk Score Analysis',
                    'timestamp': datetime.now().isoformat(),
                    'server_generated': True,
                    'rule_violation': True,
                    'platform': 'linux',
                    'desktop_environment': self._get_desktop_environment(),
                    'database_compatible': True,
                    'enhanced_processing': True,
                    'process_name': original_event.process_name,
                    'process_path': original_event.process_path
                }
                
                alerts_to_display.append(risk_alert)
                rule_violation_detected = True
                self.stats.rule_violations_received += 1
                self.stats.server_rules_triggered += 1
            
            # ENHANCED: Display alerts if any found
            if rule_violation_detected and alerts_to_display:
                self.stats.last_rule_violation = datetime.now()
                
                # Send to enhanced Linux notification system
                if self.security_notifier:
                    for alert in alerts_to_display:
                        await self.security_notifier.process_threat_response(original_event, {
                            'threat_detected': True,
                            'rule_triggered': alert.get('rule_name', alert.get('title', 'Enhanced Linux Rule')),
                            'risk_score': alert.get('risk_score', 50),
                            'threat_description': alert.get('description', 'Enhanced Linux security alert'),
                            'alerts_generated': [alert],
                            'enhanced_processing': True,
                            'database_compatible': True
                        })
                
                self.stats.rule_alerts_displayed += len(alerts_to_display)
                
                # ENHANCED: Detailed logging
                total_local = sum(1 for alert in alerts_to_display if alert.get('local_rule'))
                total_server = len(alerts_to_display) - total_local
                
                self._safe_log("warning", f"🔔 ENHANCED: DISPLAYED {len(alerts_to_display)} LINUX ALERTS")
                if total_local > 0:
                    self._safe_log("warning", f"   🔍 Enhanced Local Rules: {total_local}")
                if total_server > 0:
                    self._safe_log("warning", f"   🚨 Enhanced Server Rules: {total_server}")
                    
                # Update database response time
                response_time = time.time() - self._last_successful_send
                self._database_response_times.append(response_time)
            else:
                self._safe_log("debug", f"✅ No rule violations - Enhanced Linux processing normal")
            
        except Exception as e:
            self._safe_log("error", f"❌ Enhanced server response processing failed: {e}")
    
    def _update_severity_stats(self, severity: str):
        """Update statistics by event severity"""
        try:
            severity_lower = severity.lower()
            if severity_lower == 'critical':
                self.stats.critical_events += 1
            elif severity_lower == 'high':
                self.stats.high_events += 1
            elif severity_lower == 'medium':
                self.stats.medium_events += 1
            elif severity_lower == 'low':
                self.stats.low_events += 1
            else:
                self.stats.info_events += 1
        except Exception:
            self.stats.info_events += 1
    
    def _is_valid_linux_alert(self, alert: Dict[str, Any]) -> bool:
        """Enhanced validation for Linux alerts"""
        try:
            if not isinstance(alert, dict):
                return False
            
            # Must have basic alert structure
            has_id = alert.get('id') or alert.get('alert_id')
            has_rule = alert.get('rule_id') or alert.get('rule_name') or alert.get('rule_triggered')
            has_title = alert.get('title')
            has_description = alert.get('description')
            has_severity = alert.get('severity')
            
            # Enhanced validation - require at least 2 key fields
            field_count = sum([bool(has_id), bool(has_rule), bool(has_title), bool(has_description), bool(has_severity)])
            return field_count >= 2
            
        except Exception as e:
            self._safe_log("error", f"❌ Error validating enhanced Linux alert: {e}")
            return False
    
    def _get_desktop_environment(self) -> str:
        """Get Linux desktop environment with enhanced detection"""
        try:
            import os
            
            # Enhanced environment variable checking
            desktop_vars = [
                ('XDG_CURRENT_DESKTOP', ['GNOME', 'KDE', 'XFCE', 'MATE', 'LXDE', 'Unity', 'Cinnamon', 'Budgie', 'Pantheon']),
                ('DESKTOP_SESSION', ['gnome', 'kde', 'xfce', 'mate', 'lxde', 'unity', 'cinnamon', 'budgie', 'pantheon']),
                ('XDG_SESSION_DESKTOP', ['gnome', 'kde', 'xfce', 'mate', 'lxde', 'unity', 'cinnamon']),
                ('GDMSESSION', ['gnome', 'kde', 'xfce', 'mate', 'lxde']),
                ('KDE_FULL_SESSION', ['true']),
                ('GNOME_DESKTOP_SESSION_ID', ['*'])
            ]
            
            for env_var, values in desktop_vars:
                env_value = os.environ.get(env_var, '').lower()
                if env_value:
                    for value in values:
                        if value.lower() in env_value or value == '*':
                            return value.upper() if value != '*' else 'GNOME'
            
            # Enhanced process detection
            try:
                import subprocess
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
                processes = result.stdout.lower()
                
                desktop_processes = [
                    ('gnome-session', 'GNOME'),
                    ('kded', 'KDE'),
                    ('plasma', 'KDE'),
                    ('xfce4-session', 'XFCE'),
                    ('mate-session', 'MATE'),
                    ('lxsession', 'LXDE'),
                    ('cinnamon-session', 'Cinnamon'),
                    ('budgie-desktop', 'Budgie'),
                    ('pantheon', 'Pantheon')
                ]
                
                for process, desktop in desktop_processes:
                    if process in processes:
                        return desktop
            except:
                pass
            
            # Check for display server
            if os.environ.get('WAYLAND_DISPLAY'):
                return 'Wayland'
            elif os.environ.get('DISPLAY'):
                return 'X11'
            
            return 'Console'
            
        except Exception:
            return 'Unknown'
    
    def _map_risk_to_severity(self, risk_score: int) -> str:
        """Enhanced risk score to severity mapping"""
        if risk_score >= 95:
            return "CRITICAL"
        elif risk_score >= 85:
            return "HIGH"
        elif risk_score >= 60:
            return "MEDIUM"
        elif risk_score >= 30:
            return "LOW"
        else:
            return "INFO"
    
    async def _enhanced_retry_loop(self):
        """Enhanced retry mechanism for failed events"""
        retry_interval = 3  # Start with 3 seconds
        max_retry_interval = 45  # Max 45 seconds
        consecutive_failures = 0
        was_offline = False
        
        while self.is_running:
            try:
                if not self._failed_events_queue:
                    await asyncio.sleep(1)
                    continue
                
                # Check server connectivity
                if not self.communication or not self.communication.is_connected():
                    was_offline = True
                    await asyncio.sleep(retry_interval)
                    consecutive_failures += 1
                    retry_interval = min(retry_interval * 1.2, max_retry_interval)
                    continue
                
                # Notify when back online
                if was_offline:
                    self._safe_log("info", "✅ ENHANCED: Linux server connection restored")
                    was_offline = False
                    consecutive_failures = 0
                    retry_interval = 3
                
                # Process failed events
                failed_events = list(self._failed_events_queue)
                self._failed_events_queue.clear()
                
                success_count = 0
                for failed_event in failed_events:
                    if not self.is_running:
                        break
                    
                    event_data = failed_event['event']
                    retry_count = failed_event['retry_count']
                    
                    if retry_count >= 3:  # Max 3 retries
                        self.stats.database_errors += 1
                        continue
                    
                    try:
                        success, response, error = await self.communication.submit_event(event_data)
                        
                        if success:
                            success_count += 1
                            if response:
                                await self._process_enhanced_server_response(response, event_data)
                        else:
                            failed_event['retry_count'] = retry_count + 1
                            self._failed_events_queue.append(failed_event)
                    except Exception as e:
                        failed_event['retry_count'] = retry_count + 1
                        self._failed_events_queue.append(failed_event)
                        self.stats.database_errors += 1
                
                if success_count > 0:
                    self._safe_log("info", f"✅ ENHANCED: Sent {success_count} queued Linux events")
                
                await asyncio.sleep(retry_interval)
                
            except Exception as e:
                await asyncio.sleep(5)
    
    async def _flush_all_queues(self):
        """Flush all priority queues"""
        try:
            total_events = 0
            
            # Flush critical events first
            while self._critical_events_queue:
                event_info = self._critical_events_queue.popleft()
                await self._attempt_final_send(event_info['event'])
                total_events += 1
            
            # Flush high priority events
            while self._high_events_queue:
                event_info = self._high_events_queue.popleft()
                await self._attempt_final_send(event_info['event'])
                total_events += 1
            
            # Flush normal events (limited to prevent long delays)
            flush_count = 0
            while self._normal_events_queue and flush_count < 100:
                event_info = self._normal_events_queue.popleft()
                await self._attempt_final_send(event_info['event'])
                total_events += 1
                flush_count += 1
            
            # Attempt to send remaining failed events
            retry_count = 0
            while self._failed_events_queue and retry_count < 50:
                event_info = self._failed_events_queue.popleft()
                await self._attempt_final_send(event_info['event'])
                total_events += 1
                retry_count += 1
            
            if total_events > 0:
                self._safe_log("info", f"🔄 ENHANCED: Flushed {total_events} Linux events")
                
        except Exception as e:
            self._safe_log("error", f"❌ Enhanced queue flush error: {e}")
    
    async def _attempt_final_send(self, event_data: EventData):
        """Attempt final send of event"""
        try:
            if self.communication and self.communication.is_connected():
                success, response, error = await self.communication.submit_event(event_data)
                if success and response:
                    await self._process_enhanced_server_response(response, event_data)
        except Exception:
            pass  # Silent fail during shutdown
    
    async def _enhanced_stats_logging_loop(self):
        """Enhanced statistics logging with detailed metrics"""
        try:
            while self.is_running:
                try:
                    current_time = time.time()
                    if int(current_time) % 90 == 0:  # Every 90 seconds
                        stats = self.get_enhanced_stats()
                        
                        processing_rate = stats.get('processing_rate', 0)
                        events_sent = stats.get('events_sent', 0)
                        events_failed = stats.get('events_failed', 0)
                        success_rate = stats.get('success_rate', 0)
                        
                        # Enhanced metrics
                        critical_events = stats.get('critical_events', 0)
                        high_events = stats.get('high_events', 0)
                        local_rules = stats.get('local_rules_triggered', 0)
                        server_rules = stats.get('server_rules_triggered', 0)
                        total_alerts = stats.get('rule_alerts_displayed', 0)
                        
                        queue_status = self._get_queue_status()
                        
                        self._safe_log("info", 
                            f"📊 ENHANCED Linux Stats - "
                            f"Sent: {events_sent}, Failed: {events_failed}, "
                            f"Success: {success_rate:.1f}%, Rate: {processing_rate:.2f}/s")
                        
                        self._safe_log("info",
                            f"   🚨 Events: Critical={critical_events}, High={high_events}")
                        
                        self._safe_log("info",
                            f"   🔔 Alerts: {total_alerts} (Local: {local_rules}, Server: {server_rules})")
                        
                        self._safe_log("info",
                            f"   📋 Queues: Critical={queue_status['critical']}, "
                            f"High={queue_status['high']}, Normal={queue_status['normal']}")
                    
                    await asyncio.sleep(30)
                    
                except Exception as e:
                    self._safe_log("error", f"Enhanced stats logging error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self._safe_log("error", f"Enhanced stats logging loop failed: {e}")
    
    async def _linux_performance_monitor(self):
        """Enhanced Linux performance monitoring"""
        try:
            while self.is_running:
                try:
                    # Monitor processing performance
                    if self._event_processing_times:
                        avg_processing_time = sum(self._event_processing_times) / len(self._event_processing_times)
                        if avg_processing_time > 0.1:  # 100ms threshold
                            self._safe_log("warning", f"⚠️ High Linux processing time: {avg_processing_time:.3f}s")
                    
                    # Monitor database response times
                    if self._database_response_times:
                        avg_db_time = sum(self._database_response_times) / len(self._database_response_times)
                        if avg_db_time > 2.0:  # 2 second threshold
                            self._safe_log("warning", f"⚠️ High database response time: {avg_db_time:.1f}s")
                    
                    # Monitor queue utilization
                    queue_status = self._get_queue_status()
                    total_queued = sum(queue_status.values())
                    if total_queued > 1500:  # 75% of total capacity
                        self._safe_log("warning", f"⚠️ High queue utilization: {total_queued} events")
                    
                    # Monitor error rates
                    total_events = self.stats.events_sent + self.stats.events_failed
                    if total_events > 100:
                        error_rate = (self.stats.events_failed / total_events) * 100
                        if error_rate > 10:  # 10% error rate
                            self._safe_log("warning", f"⚠️ High error rate: {error_rate:.1f}%")
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self._safe_log("error", f"Linux performance monitor error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self._safe_log("error", f"Linux performance monitor failed: {e}")
    
    async def _database_health_monitor(self):
        """Monitor database connectivity and health"""
        try:
            while self.is_running:
                try:
                    # Test database connectivity
                    if self.communication:
                        is_connected = self.communication.is_connected()
                        
                        if not is_connected:
                            self._safe_log("warning", "⚠️ Database connection lost")
                        
                        # Log connection statistics
                        if hasattr(self.communication, 'get_server_info'):
                            server_info = self.communication.get_server_info()
                            success_rate = server_info.get('success_rate', 0)
                            
                            if success_rate < 90:  # Less than 90% success rate
                                self._safe_log("warning", f"⚠️ Low database success rate: {success_rate:.1f}%")
                    
                    await asyncio.sleep(120)  # Check every 2 minutes
                    
                except Exception as e:
                    self._safe_log("error", f"Database health monitor error: {e}")
                    await asyncio.sleep(120)
                    
        except Exception as e:
            self._safe_log("error", f"Database health monitor failed: {e}")
    
    def _get_queue_status(self) -> Dict[str, int]:
        """Get current queue status"""
        return {
            'critical': len(self._critical_events_queue),
            'high': len(self._high_events_queue),
            'normal': len(self._normal_events_queue),
            'failed': len(self._failed_events_queue)
        }
    
    async def _log_final_statistics(self):
        """Log final enhanced statistics"""
        try:
            stats = self.get_enhanced_stats()
            uptime = stats.get('uptime', 0)
            
            self._safe_log("info", "📊 ENHANCED Linux Event Processor - FINAL STATISTICS")
            self._safe_log("info", f"   ⏱️ Uptime: {uptime:.1f} seconds ({uptime/3600:.2f} hours)")
            self._safe_log("info", f"   📥 Events Collected: {stats['events_collected']}")
            self._safe_log("info", f"   📤 Events Sent: {stats['events_sent']}")
            self._safe_log("info", f"   ❌ Events Failed: {stats['events_failed']}")
            self._safe_log("info", f"   📊 Success Rate: {stats['success_rate']:.1f}%")
            self._safe_log("info", f"   🚨 Critical Events: {stats['critical_events']}")
            self._safe_log("info", f"   📈 High Events: {stats['high_events']}")
            self._safe_log("info", f"   🔔 Total Alerts: {stats['rule_alerts_displayed']}")
            self._safe_log("info", f"   🔍 Local Rules: {stats['local_rules_triggered']}")
            self._safe_log("info", f"   🚨 Server Rules: {stats['server_rules_triggered']}")
            self._safe_log("info", f"   🗄️ Database Errors: {stats['database_errors']}")
            self._safe_log("info", f"   ✅ Schema Validation Errors: {stats['schema_validation_errors']}")
            
        except Exception as e:
            self._safe_log("error", f"Final statistics logging error: {e}")
    
    def get_enhanced_stats(self) -> Dict[str, Any]:
        """Get enhanced Linux event processor statistics"""
        try:
            current_time = time.time()
            uptime = current_time - self.processing_start_time if self.processing_start_time else 0
            
            # Calculate processing rate
            processing_rate = 0
            if uptime > 0:
                processing_rate = self.stats.events_sent / uptime
            
            # Calculate success rate
            total_attempts = self.stats.events_sent + self.stats.events_failed
            success_rate = (self.stats.events_sent / total_attempts * 100) if total_attempts > 0 else 0
            
            # Calculate average processing times
            avg_processing_time = 0
            if self._event_processing_times:
                avg_processing_time = sum(self._event_processing_times) / len(self._event_processing_times)
            
            avg_db_response_time = 0
            if self._database_response_times:
                avg_db_response_time = sum(self._database_response_times) / len(self._database_response_times)
            
            return {
                'platform': 'linux',
                'processor_version': 'enhanced_v2.1',
                'desktop_environment': self._get_desktop_environment(),
                'events_collected': self.stats.events_collected,
                'events_sent': self.stats.events_sent,
                'events_failed': self.stats.events_failed,
                'rule_violations_received': self.stats.rule_violations_received,
                'rule_alerts_displayed': self.stats.rule_alerts_displayed,
                'local_rules_triggered': self.stats.local_rules_triggered,
                'server_rules_triggered': self.stats.server_rules_triggered,
                'critical_events': self.stats.critical_events,
                'high_events': self.stats.high_events,
                'medium_events': self.stats.medium_events,
                'low_events': self.stats.low_events,
                'info_events': self.stats.info_events,
                'database_errors': self.stats.database_errors,
                'schema_validation_errors': self.stats.schema_validation_errors,
                'last_event_sent': self.stats.last_event_sent.isoformat() if self.stats.last_event_sent else None,
                'last_rule_violation': self.stats.last_rule_violation.isoformat() if self.stats.last_rule_violation else None,
                'processing_rate': processing_rate,
                'success_rate': success_rate,
                'uptime': uptime,
                'send_errors': self._send_errors,
                'consecutive_failures': self._consecutive_failures,
                'time_since_last_send': current_time - self._last_successful_send,
                'queue_status': self._get_queue_status(),
                'avg_processing_time_ms': avg_processing_time * 1000,
                'avg_database_response_time_ms': avg_db_response_time * 1000,
                'enhanced_features': {
                    'priority_queuing': True,
                    'database_validation': self._database_validation_enabled,
                    'real_time_processing': self.real_time_processing,
                    'linux_optimized': True,
                    'security_notifications': self.security_notifier is not None,
                    'performance_monitoring': True
                },
                'linux_enhanced_monitoring': True,
                'database_compatible': True,
                'schema_validated': True
            }
            
        except Exception as e:
            self._safe_log("error", f"Enhanced stats calculation failed: {e}")
            return {'platform': 'linux', 'error': str(e)}
    
    # Compatibility methods for existing codebase
    async def submit_event(self, event_data: EventData):
        """Submit event - alias for add_event"""
        await self.add_event(event_data)
    
    def get_queue_size(self) -> int:
        """Get total queue size across all priorities"""
        queue_status = self._get_queue_status()
        return sum(queue_status.values())
    
    def clear_queue(self):
        """Clear all event queues"""
        self._critical_events_queue.clear()
        self._high_events_queue.clear()
        self._normal_events_queue.clear()
        self._failed_events_queue.clear()
    
    def enable_immediate_mode(self, enabled: bool = True):
        """Enable immediate mode - Always enabled for enhanced processor"""
        self.immediate_send = True
        self.real_time_processing = enabled
    
    def get_performance_metrics(self) -> Dict[str, float]:
        """Get enhanced Linux performance metrics"""
        total_attempts = self.stats.events_sent + self.stats.events_failed
        success_rate = (self.stats.events_sent / total_attempts) if total_attempts > 0 else 0
        
        queue_status = self._get_queue_status()
        total_capacity = 500 + 800 + 1500  # Critical + High + Normal
        queue_utilization = sum(queue_status.values()) / total_capacity
        
        return {
            'platform': 'linux',
            'processor_version': 'enhanced_v2.1',
            'desktop_environment': self._get_desktop_environment(),
            'queue_utilization': queue_utilization,
            'processing_rate': self.stats.processing_rate,
            'success_rate': success_rate,
            'immediate_processing': self.immediate_send,
            'real_time_processing': self.real_time_processing,
            'enhanced_rule_processing': True,
            'database_validation': self._database_validation_enabled,
            'priority_queuing': True,
            'linux_optimized': True,
            'performance_monitoring': True,
            'schema_validation': True,
            'database_compatible': True
        }