# agent/collectors/network_collector.py - FIXED Linux Network Collector
"""
Linux Network Collector - FIXED VERSION
Monitor network connections using /proc/net and psutil with corrected imports
"""

import os
import psutil
import socket
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
from collections import defaultdict, deque

from agent.collectors.base_collector import LinuxBaseCollector
from agent.schemas.events import EventData  # FIXED: Removed EventAction import

class LinuxNetworkCollector(LinuxBaseCollector):
    """Linux Network Collector with /proc/net monitoring"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "LinuxNetworkCollector")
        
        # Linux network monitoring settings
        self.polling_interval = 1.0  # 1 second, luôn quét nhanh
        self.max_events_per_batch = 20
        
        # ✅ NEW: Network event filtering configuration
        # Không lọc bất kỳ loại network event nào
        self.exclude_disconnect_events = False
        self.exclude_connect_events = False
        self.exclude_listen_events = False
        self.exclude_established_events = False
        
        # ✅ NEW: Rate limiting
        self.network_events_this_minute = 0
        self.last_network_reset = time.time()
        self.max_network_events_per_minute = self.config.get('filters', {}).get('max_network_events_per_minute', 3)
        
        # ✅ NEW: Event deduplication
        self.recent_network_events = {}
        self.network_event_dedup_window = 180  # 3 minutes
        
        # Network monitoring paths
        self.proc_net_path = Path('/proc/net')
        self.monitor_tcp = True
        self.monitor_udp = True
        self.monitor_listening_ports = True
        
        # Connection tracking
        self.monitored_connections = {}  # connection_key -> connection_info
        self.connection_history = deque(maxlen=1000)
        self.port_activity = defaultdict(int)
        self.bandwidth_usage = defaultdict(list)
        
        # Network categorization
        self.suspicious_ports = {
            22, 23, 443, 3389, 445, 135, 139, 1433, 3306, 5432,
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345,
            1337, 8080, 8443, 9050, 9051  # Additional suspicious ports
        }
        
        self.common_services = {
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'SQL Server',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        
        # Network analysis
        self.bandwidth_threshold = 10 * 1024 * 1024  # 10MB
        self.connection_rate_threshold = 50  # connections per minute
        
        # Statistics
        self.stats = {
            'connection_established_events': 0,
            'connection_closed_events': 0,
            'listening_port_events': 0,
            'suspicious_connection_events': 0,
            'external_connection_events': 0,
            'high_bandwidth_events': 0,
            'total_network_events': 0
        }
        
        self.logger.info("🐧 Linux Network Collector initialized")
    
    async def _check_collector_requirements(self):
        """Check Linux network monitoring requirements"""
        try:
            # Check if we can access /proc/net
            if not self.proc_net_path.exists():
                raise Exception("/proc/net not available")
            
            # Check specific /proc/net files
            required_files = ['tcp', 'udp', 'tcp6', 'udp6']
            available_files = []
            
            for net_file in required_files:
                file_path = self.proc_net_path / net_file
                if file_path.exists() and os.access(file_path, os.R_OK):
                    available_files.append(net_file)
                else:
                    self.logger.warning(f"⚠️ Cannot access /proc/net/{net_file}")
            
            self.logger.info(f"✅ Available /proc/net files: {available_files}")
            
            # Test psutil network functions
            try:
                psutil.net_connections()
                self.logger.info("✅ psutil network monitoring available")
            except Exception as e:
                self.logger.warning(f"⚠️ psutil network limited: {e}")
                
            # Test network tools availability
            self._check_network_tools()
                
        except Exception as e:
            self.logger.error(f"❌ Network collector requirements check failed: {e}")
            raise
    
    def _check_network_tools(self):
        """Check availability of network monitoring tools"""
        tools = ['ss', 'netstat', 'lsof']
        available_tools = []
        
        for tool in tools:
            try:
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, timeout=2)
                if result.returncode == 0:
                    available_tools.append(tool)
            except:
                try:
                    # Some tools don't have --version, try -h
                    result = subprocess.run([tool, '-h'], 
                                          capture_output=True, timeout=2)
                    available_tools.append(tool)
                except:
                    pass
        
        self.logger.info(f"✅ Available network tools: {available_tools}")
        return available_tools
    
    async def _collect_data(self):
        """Collect Linux network events"""
        try:
            start_time = time.time()
            events = []
            current_connections = {}
            
            # Get network connections using psutil
            try:
                connections = psutil.net_connections(kind='inet')
            except Exception as e:
                self.logger.debug(f"psutil net_connections failed: {e}")
                return []
            
            # Process each connection
            for conn in connections:
                try:
                    if not conn.laddr:
                        continue
                    
                    # Create unique connection key
                    conn_key = self._get_connection_key(conn)
                    current_connections[conn_key] = conn
                    
                    # Enhanced connection information
                    conn_info = await self._enhance_connection_info(conn)
                    
                    # Check for new connections
                    if conn_key not in self.monitored_connections:
                        # New connection detected
                        if conn.raddr and self._is_external_connection(conn):
                            event = await self._create_connection_established_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['connection_established_events'] += 1
                        
                        # Check for suspicious connections
                        if self._is_suspicious_connection(conn):
                            event = await self._create_suspicious_connection_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['suspicious_connection_events'] += 1
                        
                        # Check for external connections
                        if conn.raddr and self._is_external_ip(conn.raddr.ip):
                            event = await self._create_external_connection_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['external_connection_events'] += 1
                        
                        # Check for listening ports
                        if not conn.raddr and conn.status == psutil.CONN_LISTEN:
                            event = await self._create_listening_port_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['listening_port_events'] += 1
                    
                    # Update port activity tracking
                    if conn.laddr:
                        self.port_activity[conn.laddr.port] += 1
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    self.logger.debug(f"Error processing connection: {e}")
                    continue
            
            # Detect closed connections
            closed_connections = set(self.monitored_connections.keys()) - set(current_connections.keys())
            for conn_key in closed_connections:
                if conn_key in self.monitored_connections:
                    event = await self._create_connection_closed_event(conn_key, self.monitored_connections[conn_key])
                    if event:
                        events.append(event)
                        self.stats['connection_closed_events'] += 1
                    del self.monitored_connections[conn_key]
            
            # Update connection tracking
            self.monitored_connections = current_connections
            
            # Create network summary event periodically
            if self.stats['total_network_events'] % 15 == 0:
                summary_event = await self._create_network_summary_event()
                if summary_event:
                    events.append(summary_event)
            
            self.stats['total_network_events'] += len(events)
            
            # Log performance
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 2000:  # 2 seconds
                self.logger.warning(f"⚠️ Slow network collection: {collection_time:.1f}ms")
            elif events:
                self.logger.info(f"🐧 Generated {len(events)} network events ({collection_time:.1f}ms)")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Network collection failed: {e}")
            return []
    
    async def _enhance_connection_info(self, conn) -> Dict:
        """Enhance connection info with Linux-specific details"""
        try:
            conn_info = {
                'family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                'type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                'status': conn.status
            }
            
            # Get process information
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid)
                    conn_info['process_name'] = process.name()
                    conn_info['process_exe'] = process.exe()
                    conn_info['process_user'] = process.username()
                    conn_info['process_cmdline'] = ' '.join(process.cmdline())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Get service information
            if conn.laddr:
                service_name = self.common_services.get(conn.laddr.port, 'Unknown')
                conn_info['service_name'] = service_name
                conn_info['is_well_known_port'] = conn.laddr.port in self.common_services
            
            # Check if suspicious
            conn_info['is_suspicious'] = self._is_suspicious_connection(conn)
            
            # Determine direction
            conn_info['direction'] = self._determine_connection_direction(conn)
            
            return conn_info
            
        except Exception as e:
            self.logger.debug(f"Error enhancing connection info: {e}")
            return {}
    
    def _get_connection_key(self, conn) -> str:
        """Generate unique connection key"""
        try:
            if conn.raddr:
                return f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}-{conn.status}-{conn.pid}"
            else:
                return f"{conn.laddr.ip}:{conn.laddr.port}-LISTENING-{conn.status}-{conn.pid}"
        except:
            return f"unknown-{id(conn)}"
    
    def _determine_connection_direction(self, conn) -> str:
        """Determine connection direction"""
        try:
            if not conn.raddr:
                return "Listening"
            
            # Check if destination is external
            if self._is_external_ip(conn.raddr.ip):
                return "Outbound"
            
            # Check if source is external (shouldn't happen but just in case)
            if self._is_external_ip(conn.laddr.ip):
                return "Inbound"
            
            # Local connections
            if conn.raddr.ip in ['127.0.0.1', '::1']:
                return "Local"
            
            # Default to outbound for established connections
            if conn.status == psutil.CONN_ESTABLISHED:
                return "Outbound"
            
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def _is_external_connection(self, conn) -> bool:
        """Check if connection is to external IP"""
        try:
            if not conn.raddr:
                return False
            return self._is_external_ip(conn.raddr.ip)
        except:
            return False
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP address is external (not private)"""
        try:
            # Private IP ranges
            private_ranges = [
                '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.',
                '172.28.', '172.29.', '172.30.', '172.31.',
                '192.168.', '127.', '169.254.', '::1'
            ]
            return not any(ip.startswith(prefix) for prefix in private_ranges)
        except:
            return False
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Check if connection is suspicious"""
        try:
            # Check suspicious ports
            if conn.laddr and conn.laddr.port in self.suspicious_ports:
                return True
            
            if conn.raddr and conn.raddr.port in self.suspicious_ports:
                return True
            
            # Check for connections to unusual high ports
            if conn.raddr and conn.raddr.port > 49152:
                return True
            
            # Check for connections from unusual processes
            if conn.pid:
                try:
                    process = psutil.Process(conn.pid)
                    process_name = process.name().lower()
                    
                    # Suspicious process names
                    suspicious_names = ['nc', 'netcat', 'ncat', 'socat', 'telnet']
                    if any(sus_name in process_name for sus_name in suspicious_names):
                        return True
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return False
            
        except:
            return False
    
    async def _create_connection_established_event(self, conn, conn_info: Dict):
        """Create connection established event with proper agent_id - FIXED"""
        try:
            raw_event_data = {
                'platform': 'linux',
                'event_subtype': 'connection_established',
                'connection_info': conn_info,
                'service_name': conn_info.get('service_name', 'Unknown'),
                'is_well_known_port': conn_info.get('is_well_known_port', False),
                'monitoring_method': 'psutil_net_connections'
            }
            return EventData(
                event_type="Network",
                event_action="Connect",  # FIXED: Use string instead of EventAction
                event_timestamp=datetime.now(),
                severity="Medium" if conn_info.get('is_suspicious') else "Info",
                agent_id=self.agent_id,
                source_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                source_port=conn.laddr.port if conn.laddr else 0,
                destination_ip=conn.raddr.ip if conn.raddr else "0.0.0.0",
                destination_port=conn.raddr.port if conn.raddr else 0,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction=conn_info.get('direction', 'Unknown'),
                process_id=conn.pid,
                process_name=conn_info.get('process_name'),
                description=f"🐧 LINUX CONNECTION ESTABLISHED: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}",
                raw_event_data=raw_event_data
            )
        except Exception as e:
            self.logger.error(f"❌ Connection established event creation failed: {e}")
            return None
    
    async def _create_connection_closed_event(self, conn_key: str, conn):
        """Create connection closed event"""
        try:
            # Parse connection key to extract details
            parts = conn_key.split('-')
            if len(parts) >= 2:
                local_part = parts[0]
                remote_part = parts[1]
                
                # Extract addresses
                if ':' in local_part:
                    source_ip, source_port_str = local_part.rsplit(':', 1)
                    source_port = int(source_port_str) if source_port_str.isdigit() else 0
                else:
                    source_ip, source_port = "0.0.0.0", 0
                
                if remote_part == 'LISTENING':
                    destination_ip, destination_port = "0.0.0.0", 0
                    direction = "Listening"
                else:
                    if ':' in remote_part:
                        destination_ip, destination_port_str = remote_part.rsplit(':', 1)
                        destination_port = int(destination_port_str) if destination_port_str.isdigit() else 0
                    else:
                        destination_ip, destination_port = "0.0.0.0", 0
                    direction = self._determine_connection_direction(conn)
            else:
                source_ip, source_port = "0.0.0.0", 0
                destination_ip, destination_port = "0.0.0.0", 0
                direction = "Unknown"
            
            return EventData(
                event_type="Network",
                event_action="Disconnect",  # FIXED: Use string instead of EventAction
                event_timestamp=datetime.now(),
                severity="Info",
                agent_id=self.agent_id,
                source_ip=source_ip,
                source_port=source_port,
                destination_ip=destination_ip,
                destination_port=destination_port,
                protocol='TCP',
                direction=direction,
                description=f"🐧 LINUX CONNECTION CLOSED: {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'connection_closed',
                    'connection_key': conn_key,
                    'close_time': time.time(),
                    'monitoring_method': 'connection_tracking'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Connection closed event creation failed: {e}")
            return None
    
    async def _create_suspicious_connection_event(self, conn, conn_info: Dict):
        """Create suspicious connection event"""
        try:
            return EventData(
                event_type="Network",
                event_action="Suspicious",  # FIXED: Use string instead of EventAction
                event_timestamp=datetime.now(),
                severity="High",
                agent_id=self.agent_id,
                source_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                source_port=conn.laddr.port if conn.laddr else 0,
                destination_ip=conn.raddr.ip if conn.raddr else "0.0.0.0",
                destination_port=conn.raddr.port if conn.raddr else 0,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction=conn_info.get('direction', 'Unknown'),
                process_id=conn.pid,
                process_name=conn_info.get('process_name'),
                description=f"🐧 LINUX SUSPICIOUS CONNECTION: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else 'N/A'}:{conn.raddr.port if conn.raddr else 'N/A'}",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'suspicious_connection',
                    'suspicion_reason': 'suspicious_port_or_pattern',
                    'risk_level': 'high',
                    'connection_info': conn_info,
                    'service_name': conn_info.get('service_name', 'Unknown'),
                    'monitoring_method': 'connection_analysis'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Suspicious connection event creation failed: {e}")
            return None
    
    async def _create_external_connection_event(self, conn, conn_info: Dict):
        """Create external connection event"""
        try:
            return EventData(
                event_type="Network",
                event_action="Connect",  # FIXED: Use string instead of EventAction
                event_timestamp=datetime.now(),
                severity="Info",
                agent_id=self.agent_id,
                source_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                source_port=conn.laddr.port if conn.laddr else 0,
                destination_ip=conn.raddr.ip if conn.raddr else "0.0.0.0",
                destination_port=conn.raddr.port if conn.raddr else 0,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Outbound",
                process_id=conn.pid,
                process_name=conn_info.get('process_name'),
                description=f"🐧 LINUX EXTERNAL CONNECTION: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'external_connection',
                    'connection_type': 'outbound_external',
                    'destination_classification': 'external_ip',
                    'connection_info': conn_info,
                    'service_name': conn_info.get('service_name', 'Unknown'),
                    'monitoring_method': 'external_ip_detection'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ External connection event creation failed: {e}")
            return None
    
    async def _create_listening_port_event(self, conn, conn_info: Dict):
        """Create listening port event"""
        try:
            return EventData(
                event_type="Network",
                event_action="Access",  # FIXED: Use string instead of EventAction
                event_timestamp=datetime.now(),
                severity="Medium" if conn.laddr.port in self.suspicious_ports else "Info",
                agent_id=self.agent_id,
                source_ip=conn.laddr.ip if conn.laddr else "0.0.0.0",
                source_port=conn.laddr.port if conn.laddr else 0,
                destination_ip="0.0.0.0",
                destination_port=0,
                protocol='TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                direction="Listening",
                process_id=conn.pid,
                process_name=conn_info.get('process_name'),
                description=f"🐧 LINUX LISTENING PORT: {conn.laddr.ip}:{conn.laddr.port} ({conn_info.get('service_name', 'Unknown')})",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'listening_port',
                    'port': conn.laddr.port,
                    'service_name': conn_info.get('service_name', 'Unknown'),
                    'is_suspicious_port': conn.laddr.port in self.suspicious_ports,
                    'is_well_known_port': conn_info.get('is_well_known_port', False),
                    'connection_info': conn_info,
                    'bind_address': conn.laddr.ip,
                    'monitoring_method': 'listening_port_detection'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Listening port event creation failed: {e}")
            return None
    
    async def _create_network_summary_event(self):
        """Create network summary event"""
        try:
            active_connections = len(self.monitored_connections)
            
            # Count connection types
            tcp_connections = 0
            udp_connections = 0
            listening_ports = 0
            external_connections = 0
            
            for conn in self.monitored_connections.values():
                if conn.type == socket.SOCK_STREAM:
                    tcp_connections += 1
                elif conn.type == socket.SOCK_DGRAM:
                    udp_connections += 1
                
                if not conn.raddr:
                    listening_ports += 1
                elif self._is_external_connection(conn):
                    external_connections += 1
            
            return EventData(
                event_type="Network",
                event_action="Resource_Usage",  # FIXED: Use string instead of EventAction
                event_timestamp=datetime.now(),
                severity="Info",
                agent_id=self.agent_id,
                source_ip="0.0.0.0",
                source_port=0,
                destination_ip="0.0.0.0",
                destination_port=0,
                protocol="Summary",
                direction="Summary",
                description=f"🐧 LINUX NETWORK SUMMARY: {active_connections} active connections",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'network_summary',
                    'active_connections': active_connections,
                    'tcp_connections': tcp_connections,
                    'udp_connections': udp_connections,
                    'listening_ports': listening_ports,
                    'external_connections': external_connections,
                    'network_statistics': self.stats.copy(),
                    'port_activity_summary': dict(list(self.port_activity.items())[:10]),
                    'monitoring_method': 'network_summary'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Network summary event creation failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get detailed Linux network collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Linux_Network',
            'connection_established_events': self.stats['connection_established_events'],
            'connection_closed_events': self.stats['connection_closed_events'],
            'listening_port_events': self.stats['listening_port_events'],
            'suspicious_connection_events': self.stats['suspicious_connection_events'],
            'external_connection_events': self.stats['external_connection_events'],
            'high_bandwidth_events': self.stats['high_bandwidth_events'],
            'total_network_events': self.stats['total_network_events'],
            'active_connections': len(self.monitored_connections),
            'port_activity_count': len(self.port_activity),
            'proc_net_available': self.proc_net_path.exists(),
            'monitor_tcp': self.monitor_tcp,
            'monitor_udp': self.monitor_udp,
            'suspicious_ports_count': len(self.suspicious_ports),
            'common_services_count': len(self.common_services),
            'bandwidth_threshold_mb': self.bandwidth_threshold / (1024 * 1024),
            'linux_network_monitoring': True
        })
        return base_stats
    
    # ✅ NEW: Network event filtering methods
    
    def _check_network_rate_limit(self) -> bool:
        """Check if we're within network event rate limits"""
        current_time = time.time()
        
        # Reset counter every minute
        if current_time - self.last_network_reset >= 60:
            self.network_events_this_minute = 0
            self.last_network_reset = current_time
        
        if self.network_events_this_minute >= self.max_network_events_per_minute:
            return False
        
        return True
    
    def _increment_network_event_count(self):
        """Increment network event count for rate limiting"""
        self.network_events_this_minute += 1
    
    def _is_network_event_worth_sending(self, event_type: str, conn_info: Dict) -> bool:
        """Check if network event is worth sending (deduplication)"""
        try:
            # Create event key for deduplication
            local_addr = conn_info.get('local_address', 'unknown')
            remote_addr = conn_info.get('remote_address', 'unknown')
            event_key = f"network_{event_type}_{local_addr}_{remote_addr}"
            current_time = time.time()
            
            # Check if we've seen this event recently
            if event_key in self.recent_network_events:
                last_time = self.recent_network_events[event_key]
                if current_time - last_time < self.network_event_dedup_window:
                    return False
            
            # Update recent events
            self.recent_network_events[event_key] = current_time
            
            # Clean old entries
            cutoff_time = current_time - self.network_event_dedup_window
            self.recent_network_events = {
                key: timestamp for key, timestamp in self.recent_network_events.items()
                if timestamp > cutoff_time
            }
            
            return True
            
        except Exception:
            return True  # Send on error
    
    def _should_filter_network_event_type(self, event_type: str) -> bool:
        """Check if network event type should be filtered based on configuration"""
        if event_type == 'disconnect' and self.exclude_disconnect_events:
            return True
        elif event_type == 'connect' and self.exclude_connect_events:
            return True
        elif event_type == 'listen' and self.exclude_listen_events:
            return True
        elif event_type == 'established' and self.exclude_established_events:
            return True
        
        return False