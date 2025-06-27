# agent/collectors/system_collector.py - FIXED Linux System Collector
"""
Linux System Collector - FIXED VERSION
Monitor system events, services, and systemd units with corrected imports
"""

import asyncio
import logging
import time
import json
import subprocess
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from agent.collectors.base_collector import LinuxBaseCollector
from agent.schemas.events import EventData, EventSeverity

@dataclass
class SystemService:
    """System service information"""
    name: str
    status: str
    type: str
    description: str
    pid: Optional[int] = None
    memory_usage: Optional[int] = None
    cpu_usage: Optional[float] = None
    start_time: Optional[str] = None
    user: Optional[str] = None

@dataclass
class SystemEvent:
    """System event information"""
    timestamp: datetime
    event_type: str
    severity: str
    message: str
    source: str
    details: Dict[str, Any]

class LinuxSystemCollector(LinuxBaseCollector):
    """Linux System Collector - Monitor system events and services"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "LinuxSystemCollector")
        self.logger = logging.getLogger(__name__)
        
        # System monitoring
        self.systemd_available = False
        self.services_tracked = {}
        self.system_events = []
        
        # Performance monitoring
        self.performance_data = {}
        self.last_performance_check = 0
        
        # Security monitoring
        self.security_events = []
        self.failed_services = []
        self.suspicious_activities = []
        
        # Configuration
        self.monitor_systemd = True
        self.monitor_services = True
        self.monitor_system_events = True
        self.collect_performance = True
        self.security_scanning = True
        
        # ✅ NEW: Event filtering configuration
        linux_config = self.config.get('linux_specific', {})
        system_filters = linux_config.get('system_event_filters', {})
        
        self.exclude_security_events = system_filters.get('exclude_security_events', False)
        self.exclude_performance_events = system_filters.get('exclude_performance_events', True)
        self.exclude_network_events = system_filters.get('exclude_network_events', False)
        self.exclude_service_events = system_filters.get('exclude_service_events', False)
        
        # ✅ NEW: Rate limiting
        self.security_events_this_minute = 0
        self.last_security_reset = time.time()
        self.max_security_events_per_minute = self.config.get('filters', {}).get('max_security_events_per_minute', 2)
        
        # ✅ NEW: Event deduplication
        self.recent_security_events = {}
        self.security_event_dedup_window = 180  # 3 minutes
        
        # Monitoring intervals
        self.service_check_interval = 30
        self.performance_check_interval = 60
        self.security_check_interval = 120
        
        # Statistics
        self.stats = {
            'service_events': 0,
            'system_events': 0,
            'performance_events': 0,
            'security_events': 0,
            'total_system_events': 0,
            'filtered_security_events': 0,
            'rate_limited_security_events': 0
        }
        
    async def initialize(self):
        """Initialize system collector"""
        try:
            self.logger.info("💻 Initializing Linux System Collector...")
            
            # Check for systemd
            await self._check_systemd_availability()
            
            # Initialize service tracking
            if self.monitor_services:
                await self._initialize_service_tracking()
            
            # Setup system event monitoring
            if self.monitor_system_events:
                await self._setup_system_event_monitoring()
            
            # Initialize performance monitoring
            if self.collect_performance:
                await self._initialize_performance_monitoring()
            
            # Setup security monitoring
            if self.security_scanning:
                await self._setup_security_monitoring()
            
            self.logger.info("✅ System Collector initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ System Collector initialization failed: {e}")
            raise
    
    async def _check_systemd_availability(self):
        """Check if systemd is available"""
        try:
            result = subprocess.run(
                ['systemctl', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode == 0:
                self.systemd_available = True
                self.logger.info(f"⚙️ systemd detected: {result.stdout.strip()}")
            else:
                self.logger.warning("⚠️ systemd not available")
                
        except Exception as e:
            self.logger.warning(f"⚠️ systemd check failed: {e}")
    
    async def _initialize_service_tracking(self):
        """Initialize service tracking"""
        try:
            if not self.systemd_available:
                self.logger.warning("⚠️ Skipping service tracking - systemd not available")
                return
            
            # Get all systemd services
            services = await self._get_systemd_services()
            
            for service in services:
                self.services_tracked[service.name] = {
                    'service': service,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'status_history': [service.status],
                    'events': []
                }
            
            self.logger.info(f"📊 Tracking {len(self.services_tracked)} systemd services")
            
        except Exception as e:
            self.logger.error(f"❌ Service tracking initialization failed: {e}")
    
    async def _setup_system_event_monitoring(self):
        """Setup system event monitoring"""
        try:
            # Check for journalctl availability
            result = subprocess.run(
                ['journalctl', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode == 0:
                self.logger.info("📰 journalctl available for system event monitoring")
            else:
                self.logger.warning("⚠️ journalctl not available")
            
        except Exception as e:
            self.logger.warning(f"⚠️ System event monitoring setup failed: {e}")
    
    async def _initialize_performance_monitoring(self):
        """Initialize performance monitoring"""
        try:
            # Get initial system performance data
            self.performance_data = await self._get_system_performance()
            self.last_performance_check = time.time()
            
            self.logger.info("📈 Performance monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Performance monitoring initialization failed: {e}")
    
    async def _setup_security_monitoring(self):
        """Setup security monitoring"""
        try:
            # Check for failed services
            failed_services = await self._find_failed_services()
            
            for service in failed_services:
                await self._report_security_event(
                    service_name=service.name,
                    event_type="failed_service_detected",
                    severity=EventSeverity.MEDIUM,
                    details={
                        'service_name': service.name,
                        'status': service.status,
                        'description': service.description
                    }
                )
            
            # Check for suspicious system activities
            suspicious_activities = await self._find_suspicious_activities()
            
            for activity in suspicious_activities:
                await self._report_security_event(
                    service_name="system",
                    event_type="suspicious_system_activity",
                    severity=EventSeverity.MEDIUM,
                    details=activity
                )
            
        except Exception as e:
            self.logger.error(f"❌ Security monitoring setup failed: {e}")
    
    async def _collect_data(self):
        """✅ FIXED: Implement abstract method for Linux system data collection"""
        try:
            if not self.is_running:
                return []
            
            events = []
            
            # Monitor services
            if self.monitor_services and self.systemd_available:
                service_events = await self._monitor_services()
                events.extend(service_events)
            
            # Monitor system events
            if self.monitor_system_events:
                system_events = await self._monitor_system_events()
                events.extend(system_events)
            
            # Collect performance data
            if self.collect_performance and time.time() - self.last_performance_check > self.performance_check_interval:
                performance_events = await self._collect_performance_data()
                events.extend(performance_events)
                self.last_performance_check = time.time()
            
            # Security scanning
            if self.security_scanning and time.time() % self.security_check_interval < 5:
                security_events = await self._perform_security_scan()
                events.extend(security_events)
            
            self.stats['total_system_events'] += len(events)
            return events
            
        except Exception as e:
            self.logger.error(f"❌ System data collection failed: {e}")
            return []
    
    async def _monitor_services(self):
        """Monitor systemd services and return events"""
        events = []
        try:
            current_services = await self._get_systemd_services()
            current_service_names = {s.name for s in current_services}
            
            # Check for new services
            for service in current_services:
                if service.name not in self.services_tracked:
                    await self._handle_new_service(service)
                    event = await self._create_service_event(service, "service_started")
                    if event:
                        events.append(event)
                        self.stats['service_events'] += 1
                else:
                    # Update existing service
                    await self._update_service_info(service)
            
            # Check for removed services
            tracked_names = set(self.services_tracked.keys())
            removed_services = tracked_names - current_service_names
            
            for service_name in removed_services:
                await self._handle_removed_service(service_name)
                event = await self._create_service_event(
                    SystemService(name=service_name, status="stopped", type="unknown", description="Service stopped"),
                    "service_stopped"
                )
                if event:
                    events.append(event)
                    self.stats['service_events'] += 1
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Service monitoring failed: {e}")
            return events
    
    async def _get_systemd_services(self) -> List[SystemService]:
        """Get systemd services"""
        services = []
        
        try:
            # Get active services
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--no-legend'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        service = self._parse_systemd_service_line(line)
                        if service:
                            services.append(service)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to get systemd services: {e}")
        
        return services
    
    def _parse_systemd_service_line(self, line: str) -> Optional[SystemService]:
        """Parse systemd service line"""
        try:
            # Format: UNIT LOAD ACTIVE SUB DESCRIPTION
            parts = line.split()
            if len(parts) >= 5:
                name = parts[0]
                load = parts[1]
                active = parts[2]
                sub = parts[3]
                description = ' '.join(parts[4:])
                
                # Determine status
                if active == 'active' and sub in ['running', 'exited']:
                    status = 'running' if sub == 'running' else 'exited'
                elif load == 'loaded':
                    status = 'loaded'
                else:
                    status = 'inactive'
                
                return SystemService(
                    name=name,
                    status=status,
                    type='systemd',
                    description=description
                )
        
        except Exception as e:
            self.logger.debug(f"Failed to parse service line: {e}")
        
        return None
    
    async def _handle_new_service(self, service: SystemService):
        """Handle new service detection"""
        try:
            self.logger.info(f"🆕 New service detected: {service.name}")
            
            # Add to tracking
            self.services_tracked[service.name] = {
                'service': service,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'status_history': [service.status],
                'events': []
            }
            
            # Create event
            event_data = EventData(
                event_type="System",
                event_action="Service_Start",
                severity=EventSeverity.INFO.value,
                agent_id=self.agent_id,
                description=f"Service started: {service.name}",
                raw_event_data={
                    'service_name': service.name,
                    'status': service.status,
                    'description': service.description,
                    'type': service.type
                }
            )
            
            await self._send_event_immediately(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ New service handling failed: {e}")
    
    async def _update_service_info(self, service: SystemService):
        """Update existing service information"""
        try:
            if service.name in self.services_tracked:
                tracking_info = self.services_tracked[service.name]
                old_status = tracking_info['service'].status
                
                # Update tracking info
                tracking_info['service'] = service
                tracking_info['last_seen'] = datetime.now()
                tracking_info['status_history'].append(service.status)
                
                # Check for status change
                if old_status != service.status:
                    self.logger.info(f"🔄 Service status changed: {service.name} - {old_status} -> {service.status}")
                    
                    event_action = "Service_Start" if service.status == 'running' else "Service_Stop"
                    
                    event_data = EventData(
                        event_type="System",
                        event_action=event_action,
                        severity=EventSeverity.INFO.value,
                        agent_id=self.agent_id,
                        description=f"Service status changed: {service.name} - {old_status} -> {service.status}",
                        raw_event_data={
                            'service_name': service.name,
                            'old_status': old_status,
                            'new_status': service.status,
                            'description': service.description
                        }
                    )
                    
                    await self._send_event_immediately(event_data)
                    
                    # Check for failed services
                    if service.status == 'failed':
                        await self._report_security_event(
                            service_name=service.name,
                            event_type="service_failed",
                            severity=EventSeverity.MEDIUM,
                            details={
                                'service_name': service.name,
                                'description': service.description
                            }
                        )
        
        except Exception as e:
            self.logger.error(f"❌ Service info update failed: {e}")
    
    async def _handle_removed_service(self, service_name: str):
        """Handle service removal"""
        try:
            if service_name in self.services_tracked:
                service_info = self.services_tracked[service_name]
                service = service_info['service']
                
                self.logger.info(f"🗑️ Service removed: {service_name}")
                
                # Create event
                event_data = EventData(
                    event_type="System",
                    event_action="Service_Stop",
                    severity=EventSeverity.INFO.value,
                    agent_id=self.agent_id,
                    description=f"Service removed: {service_name}",
                    raw_event_data={
                        'service_name': service_name,
                        'description': service.description,
                        'lifetime_seconds': (datetime.now() - service_info['first_seen']).total_seconds()
                    }
                )
                
                await self._send_event_immediately(event_data)
                
                # Remove from tracking
                del self.services_tracked[service_name]
        
        except Exception as e:
            self.logger.error(f"❌ Service removal handling failed: {e}")
    
    async def _monitor_system_events(self):
        """Monitor system events and return events"""
        events = []
        try:
            system_events = await self._get_system_events()
            
            for event in system_events:
                if self._is_security_event(event):
                    security_event = await self._create_security_event(event)
                    if security_event:
                        events.append(security_event)
                        self.stats['security_events'] += 1
                else:
                    system_event = await self._create_system_event(event)
                    if system_event:
                        events.append(system_event)
                        self.stats['system_events'] += 1
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ System event monitoring failed: {e}")
            return events
    
    async def _get_system_events(self) -> List[SystemEvent]:
        """Get recent system events from journalctl"""
        events = []
        
        try:
            # Get recent system events
            result = subprocess.run(
                ['journalctl', '--since', '1 minute ago', '--no-pager', '--output=json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            event = self._parse_journal_event(data)
                            if event:
                                events.append(event)
                        except json.JSONDecodeError:
                            continue
            
        except Exception as e:
            self.logger.error(f"❌ Failed to get system events: {e}")
        
        return events
    
    def _parse_journal_event(self, data: Dict) -> Optional[SystemEvent]:
        """Parse journalctl event"""
        try:
            timestamp = datetime.fromtimestamp(float(data.get('__REALTIME_TIMESTAMP', 0)) / 1000000)
            
            return SystemEvent(
                timestamp=timestamp,
                event_type=data.get('MESSAGE', 'unknown'),
                severity=data.get('PRIORITY', 'info'),
                message=data.get('MESSAGE', ''),
                source=data.get('_SYSTEMD_UNIT', 'unknown'),
                details=data
            )
        
        except Exception as e:
            self.logger.debug(f"Failed to parse journal event: {e}")
        
        return None
    
    def _is_security_event(self, event: SystemEvent) -> bool:
        """Check if event is security-relevant"""
        security_keywords = [
            'failed', 'error', 'denied', 'unauthorized', 'suspicious',
            'attack', 'intrusion', 'breach', 'malware', 'virus',
            'root', 'sudo', 'su', 'authentication', 'login'
        ]
        
        message_lower = event.message.lower()
        return any(keyword in message_lower for keyword in security_keywords)
    
    async def _collect_performance_data(self):
        """Collect performance data and return events"""
        events = []
        try:
            new_performance = await self._get_system_performance()
            
            if self.performance_data:
                changes = self._detect_performance_changes(self.performance_data, new_performance)
                
                for change in changes:
                    performance_event = await self._create_performance_event(change)
                    if performance_event:
                        events.append(performance_event)
                        self.stats['performance_events'] += 1
            
            self.performance_data = new_performance
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Performance data collection failed: {e}")
            return events
    
    async def _get_system_performance(self) -> Dict[str, Any]:
        """Get system performance data"""
        try:
            performance = {}
            
            # CPU usage
            try:
                with open('/proc/loadavg', 'r') as f:
                    load_avg = f.read().strip().split()
                    performance['load_average'] = {
                        '1min': float(load_avg[0]),
                        '5min': float(load_avg[1]),
                        '15min': float(load_avg[2])
                    }
            except:
                pass
            
            # Memory usage
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            meminfo[key.strip()] = int(value.strip().split()[0]) * 1024
                    
                    performance['memory'] = {
                        'total': meminfo.get('MemTotal', 0),
                        'available': meminfo.get('MemAvailable', 0),
                        'used': meminfo.get('MemTotal', 0) - meminfo.get('MemAvailable', 0),
                        'free': meminfo.get('MemFree', 0)
                    }
            except:
                pass
            
            # Disk usage
            try:
                result = subprocess.run(
                    ['df', '/', '--output=size,used,avail', '--block-size=1'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        parts = lines[1].split()
                        if len(parts) >= 3:
                            performance['disk'] = {
                                'total': int(parts[0]),
                                'used': int(parts[1]),
                                'available': int(parts[2])
                            }
            except:
                pass
            
            # Network statistics
            try:
                with open('/proc/net/dev', 'r') as f:
                    net_stats = {}
                    for line in f:
                        if ':' in line and not line.startswith('Inter-'):
                            parts = line.split()
                            if len(parts) >= 10:
                                interface = parts[0].rstrip(':')
                                net_stats[interface] = {
                                    'rx_bytes': int(parts[1]),
                                    'tx_bytes': int(parts[9])
                                }
                    performance['network'] = net_stats
            except:
                pass
            
            return performance
            
        except Exception as e:
            self.logger.error(f"❌ Failed to get system performance: {e}")
            return {}
    
    def _detect_performance_changes(self, old_data: Dict, new_data: Dict) -> List[Dict]:
        """Detect significant performance changes"""
        changes = []
        
        try:
            # Check load average changes
            if 'load_average' in old_data and 'load_average' in new_data:
                old_load = old_data['load_average']['5min']
                new_load = new_data['load_average']['5min']
                
                if new_load > old_load * 1.5:  # 50% increase
                    changes.append({
                        'type': 'high_load_detected',
                        'old_load': old_load,
                        'new_load': new_load,
                        'increase_percent': ((new_load - old_load) / old_load) * 100
                    })
            
            # Check memory usage changes
            if 'memory' in old_data and 'memory' in new_data:
                old_mem = old_data['memory']
                new_mem = new_data['memory']
                
                old_usage_percent = (old_mem['used'] / old_mem['total']) * 100
                new_usage_percent = (new_mem['used'] / new_mem['total']) * 100
                
                if new_usage_percent > 90:  # High memory usage
                    changes.append({
                        'type': 'high_memory_usage',
                        'usage_percent': new_usage_percent,
                        'available_mb': new_mem['available'] / (1024 * 1024)
                    })
            
            # Check disk usage changes
            if 'disk' in old_data and 'disk' in new_data:
                old_disk = old_data['disk']
                new_disk = new_data['disk']
                
                old_usage_percent = (old_disk['used'] / old_disk['total']) * 100
                new_usage_percent = (new_disk['used'] / new_disk['total']) * 100
                
                if new_usage_percent > 90:  # High disk usage
                    changes.append({
                        'type': 'high_disk_usage',
                        'usage_percent': new_usage_percent,
                        'available_gb': new_disk['available'] / (1024 * 1024 * 1024)
                    })
        
        except Exception as e:
            self.logger.error(f"❌ Performance change detection failed: {e}")
        
        return changes
    
    async def _perform_security_scan(self):
        """Perform security scan and return events"""
        events = []
        try:
            # Check for failed services
            failed_services = await self._find_failed_services()
            
            for service in failed_services:
                security_event = await self._create_security_event_from_service(service)
                if security_event:
                    events.append(security_event)
                    self.stats['security_events'] += 1
            
            # Check for suspicious activities
            suspicious_activities = await self._find_suspicious_activities()
            
            for activity in suspicious_activities:
                security_event = await self._create_security_event_from_activity(activity)
                if security_event:
                    events.append(security_event)
                    self.stats['security_events'] += 1
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Security scan failed: {e}")
            return events
    
    async def _find_failed_services(self) -> List[SystemService]:
        """Find failed services"""
        failed = []
        
        try:
            if self.systemd_available:
                result = subprocess.run(
                    ['systemctl', 'list-units', '--type=service', '--state=failed', '--no-pager', '--no-legend'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            service = self._parse_systemd_service_line(line)
                            if service:
                                failed.append(service)
        
        except Exception as e:
            self.logger.error(f"❌ Failed service search failed: {e}")
        
        return failed
    
    async def _find_suspicious_activities(self) -> List[Dict]:
        """Find suspicious system activities"""
        activities = []
        
        try:
            # Check for unusual process activities
            result = subprocess.run(
                ['ps', 'aux', '--sort=-%cpu'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines[:10]:  # Check top 10 processes
                    parts = line.split()
                    if len(parts) >= 3:
                        cpu_usage = float(parts[2])
                        if cpu_usage > 80:  # High CPU usage
                            activities.append({
                                'type': 'high_cpu_process',
                                'process': parts[10] if len(parts) > 10 else 'unknown',
                                'cpu_usage': cpu_usage,
                                'user': parts[0]
                            })
            
            # Check for unusual network connections
            result = subprocess.run(
                ['ss', '-tuln'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            port = parts[3].split(':')[-1]
                            if port in ['22', '23', '3389', '5900']:  # Common remote access ports
                                activities.append({
                                    'type': 'remote_access_port',
                                    'port': port,
                                    'protocol': parts[0]
                                })
        
        except Exception as e:
            self.logger.error(f"❌ Suspicious activity search failed: {e}")
        
        return activities
    
    async def _report_security_event(self, service_name: str, event_type: str, severity: EventSeverity, details: Dict):
        """Report security event"""
        try:
            event_data = EventData(
                event_type="System",
                event_action="Security_Event",
                severity=severity.value,
                agent_id=self.agent_id,
                description=f"Security event: {event_type}",
                raw_event_data={
                    'service_name': service_name,
                    'security_event_type': event_type,
                    'details': details
                }
            )
            
            await self._send_event_immediately(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ Security event reporting failed: {e}")
    
    async def _create_service_event(self, service: SystemService, event_type: str) -> Optional[EventData]:
        """Create service event with proper agent_id"""
        try:
            severity = "Medium" if event_type in ["service_stopped", "service_failed"] else "Info"
            
            return EventData(
                event_type="System",
                event_action=event_type.upper(),
                event_timestamp=datetime.now(),
                severity=severity,
                agent_id=self.agent_id,
                description=f"🐧 LINUX SERVICE {event_type.upper()}: {service.name} ({service.status})",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'service_monitoring',
                    'service_name': service.name,
                    'service_status': service.status,
                    'service_type': service.type,
                    'service_description': service.description,
                    'service_pid': service.pid,
                    'service_user': service.user,
                    'monitoring_method': 'systemd_service_tracking'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Service event creation failed: {e}")
            return None

    async def _create_system_event(self, event: SystemEvent) -> Optional[EventData]:
        """Create system event with proper agent_id"""
        try:
            return EventData(
                event_type="System",
                event_action="SYSTEM_EVENT",
                event_timestamp=event.timestamp,
                severity=event.severity.upper(),
                agent_id=self.agent_id,
                description=f"🐧 LINUX SYSTEM EVENT: {event.message}",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'system_event',
                    'event_source': event.source,
                    'event_message': event.message,
                    'event_details': event.details,
                    'monitoring_method': 'journalctl_system_events'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ System event creation failed: {e}")
            return None

    async def _create_security_event(self, event: SystemEvent) -> Optional[EventData]:
        """Create security event with proper agent_id"""
        try:
            return EventData(
                event_type="System",
                event_action="SECURITY_EVENT",
                event_timestamp=event.timestamp,
                severity="High",
                agent_id=self.agent_id,
                description=f"🚨 LINUX SECURITY EVENT: {event.message}",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'security_event',
                    'event_source': event.source,
                    'event_message': event.message,
                    'event_details': event.details,
                    'security_level': 'high',
                    'monitoring_method': 'journalctl_security_events'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Security event creation failed: {e}")
            return None

    async def _create_performance_event(self, change: Dict) -> Optional[EventData]:
        """Create performance event with proper agent_id"""
        try:
            return EventData(
                event_type="System",
                event_action="PERFORMANCE_CHANGE",
                event_timestamp=datetime.now(),
                severity="Medium",
                agent_id=self.agent_id,
                description=f"📈 LINUX PERFORMANCE: {change.get('metric', 'Unknown')} changed",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'performance_monitoring',
                    'metric': change.get('metric'),
                    'old_value': change.get('old_value'),
                    'new_value': change.get('new_value'),
                    'change_percent': change.get('change_percent'),
                    'threshold': change.get('threshold'),
                    'monitoring_method': 'system_performance_tracking'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Performance event creation failed: {e}")
            return None

    async def _create_security_event_from_service(self, service: SystemService) -> Optional[EventData]:
        """Create security event from failed service"""
        try:
            return EventData(
                event_type="System",
                event_action="SECURITY_EVENT",
                event_timestamp=datetime.now(),
                severity="Medium",
                agent_id=self.agent_id,
                description=f"🚨 LINUX FAILED SERVICE: {service.name}",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'failed_service',
                    'service_name': service.name,
                    'service_status': service.status,
                    'service_description': service.description,
                    'security_level': 'medium',
                    'monitoring_method': 'systemd_service_monitoring'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Security event creation failed: {e}")
            return None

    async def _create_security_event_from_activity(self, activity: Dict) -> Optional[EventData]:
        """Create security event from suspicious activity"""
        try:
            return EventData(
                event_type="System",
                event_action="SECURITY_EVENT",
                event_timestamp=datetime.now(),
                severity="Medium",
                agent_id=self.agent_id,
                description=f"🚨 LINUX SUSPICIOUS ACTIVITY: {activity.get('type', 'Unknown')}",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'suspicious_activity',
                    'activity_type': activity.get('type'),
                    'activity_details': activity.get('details'),
                    'security_level': 'medium',
                    'monitoring_method': 'system_security_scanning'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Security event creation failed: {e}")
            return None

    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            'collector_type': 'system',
            'is_running': self.is_running,
            'systemd_available': self.systemd_available,
            'services_tracked': len(self.services_tracked),
            'system_events': len(self.system_events),
            'security_events': len(self.security_events),
            'failed_services': len(self.failed_services),
            'suspicious_activities': len(self.suspicious_activities)
        }

    # ✅ NEW: Security event filtering methods
    
    def _check_security_rate_limit(self) -> bool:
        """Check if we're within security event rate limits"""
        current_time = time.time()
        
        # Reset counter every minute
        if current_time - self.last_security_reset >= 60:
            self.security_events_this_minute = 0
            self.last_security_reset = current_time
        
        if self.security_events_this_minute >= self.max_security_events_per_minute:
            self.stats['rate_limited_security_events'] += 1
            return False
        
        return True
    
    def _increment_security_event_count(self):
        """Increment security event count for rate limiting"""
        self.security_events_this_minute += 1
    
    def _is_security_event_worth_sending(self, event_type: str, details: Dict) -> bool:
        """Check if security event is worth sending (deduplication)"""
        try:
            # Create event key for deduplication
            event_key = f"security_{event_type}_{details.get('service_name', 'unknown')}"
            current_time = time.time()
            
            # Check if we've seen this event recently
            if event_key in self.recent_security_events:
                last_time = self.recent_security_events[event_key]
                if current_time - last_time < self.security_event_dedup_window:
                    self.stats['filtered_security_events'] += 1
                    return False
            
            # Update recent events
            self.recent_security_events[event_key] = current_time
            
            # Clean old entries
            cutoff_time = current_time - self.security_event_dedup_window
            self.recent_security_events = {
                key: timestamp for key, timestamp in self.recent_security_events.items()
                if timestamp > cutoff_time
            }
            
            return True
            
        except Exception:
            return True  # Send on error
    
    def _should_filter_event_type(self, event_type: str) -> bool:
        """Check if event type should be filtered based on configuration"""
        if event_type == 'security' and self.exclude_security_events:
            return True
        elif event_type == 'performance' and self.exclude_performance_events:
            return True
        elif event_type == 'network' and self.exclude_network_events:
            return True
        elif event_type == 'service' and self.exclude_service_events:
            return True
        
        return False