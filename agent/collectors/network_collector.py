# agent/collectors/network_collector.py - ENHANCED Linux Network Collector
"""
ENHANCED Linux Network Collector - Complete Data Collection
Thu thập đầy đủ thông tin network: SourceIP, DestinationIP, SourcePort, DestinationPort, Protocol, Direction
Dựa trên Windows Network Collector để đảm bảo thu thập đầy đủ dữ liệu
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
from agent.schemas.events import EventData

class EnhancedLinuxNetworkCollector(LinuxBaseCollector):
    """ENHANCED Linux Network Collector - Complete Data Collection"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "EnhancedLinuxNetworkCollector")
        
        # ✅ ENHANCED: Network monitoring settings
        self.polling_interval = 0.5  # 500ms for real-time monitoring
        self.max_events_per_batch = 100  # Increased for better coverage
        
        # ✅ ENHANCED: Network event filtering configuration
        self.exclude_disconnect_events = False
        self.exclude_connect_events = False
        self.exclude_listen_events = False
        self.exclude_established_events = False
        
        # ✅ ENHANCED: Rate limiting - Increased for better coverage
        self.network_events_this_minute = 0
        self.last_network_reset = time.time()
        self.max_network_events_per_minute = 200  # Increased from 100
        
        # ✅ ENHANCED: Event deduplication
        self.recent_network_events = {}
        self.network_event_dedup_window = 30  # Reduced for more frequent updates
        
        # Network monitoring paths
        self.proc_net_path = Path('/proc/net')
        self.monitor_tcp = True
        self.monitor_udp = True
        self.monitor_listening_ports = True
        
        # ✅ ENHANCED: Connection tracking
        self.monitored_connections = {}  # connection_key -> connection_info
        self.connection_history = deque(maxlen=2000)  # Increased
        self.port_activity = defaultdict(int)
        self.bandwidth_usage = defaultdict(list)
        self.dns_queries = deque(maxlen=1000)  # Added DNS tracking
        
        # ✅ ENHANCED: Network categorization
        self.suspicious_ports = {
            22, 23, 443, 3389, 445, 135, 139, 1433, 3306, 5432,
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345,
            1337, 8080, 8443, 9050, 9051, 1080, 3128, 8081
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
            27017: 'MongoDB',
            21: 'FTP',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            1080: 'SOCKS',
            3128: 'HTTP-Proxy'
        }
        
        # ✅ ENHANCED: Network analysis
        self.bandwidth_threshold = 10 * 1024 * 1024  # 10MB
        self.connection_rate_threshold = 100  # Increased
        
        # ✅ ENHANCED: Statistics
        self.stats = {
            'connection_established_events': 0,
            'connection_closed_events': 0,
            'listening_port_events': 0,
            'suspicious_connection_events': 0,
            'external_connection_events': 0,
            'high_bandwidth_events': 0,
            'port_scan_events': 0,
            'dns_query_events': 0,
            'network_summary_events': 0,
            'firewall_events': 0,
            'total_network_events': 0,
            'all_connection_events': 0
        }
        
        self.logger.info("🐧 ENHANCED Linux Network Collector initialized")
        self.logger.info(f"📊 Rate limit: {self.max_network_events_per_minute} events/minute")
        self.logger.info(f"🔍 Suspicious ports: {sorted(self.suspicious_ports)}")
        self.logger.info(f"🌐 Complete data collection: ALL network fields populated")
    
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
                connections = psutil.net_connections()
                self.logger.info(f"✅ psutil network monitoring available - {len(connections)} connections found")
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
        """✅ ENHANCED: Collect Linux network events with complete data"""
        try:
            start_time = time.time()
            events = []
            current_connections = {}
            
            # ✅ ENHANCED: Check server connectivity before processing
            is_connected = False
            if hasattr(self, 'event_processor') and self.event_processor:
                if hasattr(self.event_processor, 'communication') and self.event_processor.communication:
                    is_connected = not self.event_processor.communication.offline_mode
            
            # Get network connections using psutil
            try:
                connections = psutil.net_connections(kind='inet')
                self.logger.debug(f"🔍 Found {len(connections)} network connections")
            except Exception as e:
                self.logger.debug(f"psutil net_connections failed: {e}")
                return []
            
            # ✅ ENHANCED: Process each connection with complete data
            for conn in connections:
                try:
                    if not conn.laddr:
                        continue
                    
                    # Create unique connection key
                    conn_key = self._get_connection_key(conn)
                    current_connections[conn_key] = conn
                    
                    # ✅ ENHANCED: Enhanced connection information
                    conn_info = await self._enhance_connection_info(conn)
                    
                    # ✅ ENHANCED: Check for new connections - LOG ALL NEW CONNECTIONS
                    if conn_key not in self.monitored_connections:
                        # EVENT TYPE 1: New Connection Established Event with COMPLETE data
                        if conn.raddr:  # Has remote address (outbound/inbound)
                            event = await self._create_complete_connection_established_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['connection_established_events'] += 1
                                self.stats['all_connection_events'] += 1
                                
                                # ✅ ENHANCED LOGGING: Log every connection with details
                                is_external = self._is_external_ip(conn.raddr.ip) if conn.raddr else False
                                is_suspicious = conn_info.get('is_suspicious', False)
                                process_name = conn_info.get('process_name', 'Unknown')
                                
                                log_level = "WARNING" if is_suspicious else "INFO"
                                ip_type = "EXTERNAL" if is_external else "PRIVATE"
                                suspicion_flag = " ⚠️ SUSPICIOUS" if is_suspicious else ""
                                
                                self.logger.info(f"🔗 NEW CONNECTION [{ip_type}]: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port} | Process: {process_name}{suspicion_flag}")
                        
                        # EVENT TYPE 2: Suspicious Connection Event with COMPLETE data
                        if self._is_suspicious_connection(conn):
                            event = await self._create_complete_suspicious_connection_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['suspicious_connection_events'] += 1
                                self.logger.warning(f"⚠️ SUSPICIOUS CONNECTION: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else 'N/A'}:{conn.raddr.port if conn.raddr else 'N/A'} | Process: {conn_info.get('process_name', 'Unknown')}")
                        
                        # EVENT TYPE 3: External Connection Event with COMPLETE data
                        if conn.raddr and self._is_external_ip(conn.raddr.ip):
                            event = await self._create_complete_external_connection_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['external_connection_events'] += 1
                        
                        # EVENT TYPE 4: Listening Port Event with COMPLETE data
                        if not conn.raddr and conn.status == psutil.CONN_LISTEN:
                            event = await self._create_complete_listening_port_event(conn, conn_info)
                            if event:
                                events.append(event)
                                self.stats['listening_port_events'] += 1
                                self.logger.info(f"👂 LISTENING PORT: {conn.laddr.ip}:{conn.laddr.port} | Process: {conn_info.get('process_name', 'Unknown')}")
                    
                    # Update port activity tracking
                    if conn.laddr:
                        self.port_activity[conn.laddr.port] += 1
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception as e:
                    self.logger.debug(f"Error processing connection: {e}")
                    continue
            
            # ✅ ENHANCED: EVENT TYPE 5: Connection Closed Events with COMPLETE data
            closed_connections = set(self.monitored_connections.keys()) - set(current_connections.keys())
            for conn_key in closed_connections:
                if conn_key in self.monitored_connections:
                    old_conn = self.monitored_connections[conn_key]
                    event = await self._create_complete_connection_closed_event(conn_key, old_conn)
                    if event:
                        events.append(event)
                        self.stats['connection_closed_events'] += 1
                        
                        # ✅ ENHANCED LOGGING: Log connection closures
                        if old_conn.laddr and old_conn.raddr:
                            self.logger.info(f"🔌 CONNECTION CLOSED: {old_conn.laddr.ip}:{old_conn.laddr.port} -> {old_conn.raddr.ip}:{old_conn.raddr.port}")
                    
                    del self.monitored_connections[conn_key]
            
            # ✅ ENHANCED: EVENT TYPE 6: Network Summary Event (every 15 scans)
            if self.stats['total_network_events'] % 15 == 0:
                summary_event = await self._create_complete_network_summary_event()
                if summary_event:
                    events.append(summary_event)
                    self.stats['network_summary_events'] += 1
            
            # Update connection tracking
            self.monitored_connections = current_connections
            self.stats['total_network_events'] += len(events)
            
            # ✅ ENHANCED: Only log events when connected to server
            if events and is_connected:
                self.logger.info(f"📤 Generated {len(events)} COMPLETE NETWORK EVENTS")
                # Log sample event details
                for event in events[:3]:  # Log first 3 events
                    self.logger.info(f"📤 Network event: {event.source_ip}:{event.source_port} -> {event.destination_ip}:{event.destination_port} ({event.protocol})")
            
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
        """✅ FIXED: Determine connection direction with proper logic"""
        try:
            if not conn.raddr:
                return "Listening"
            
            # ✅ FIXED: Check if destination is external
            if self._is_external_ip(conn.raddr.ip):
                return "Outbound"
            
            # ✅ FIXED: Check if source is external (inbound connection)
            if self._is_external_ip(conn.laddr.ip):
                return "Inbound"
            
            # ✅ FIXED: Local connections (localhost)
            if conn.raddr.ip in ['127.0.0.1', '::1']:
                return "Local"
            
            # ✅ FIXED: Private-to-private connections should be Outbound
            # This fixes the issue where 192.168.x.x -> 192.168.x.x was returning "Unknown"
            if (not self._is_external_ip(conn.laddr.ip) and 
                not self._is_external_ip(conn.raddr.ip) and
                conn.laddr.ip != conn.raddr.ip):
                return "Outbound"
            
            # ✅ FIXED: Default to outbound for established connections
            if hasattr(conn, 'status') and conn.status == psutil.CONN_ESTABLISHED:
                return "Outbound"
            
            # ✅ FIXED: For any connection with remote address, default to Outbound
            if conn.raddr:
                return "Outbound"
            
            return "Unknown"
            
        except Exception as e:
            self.logger.debug(f"Direction determination failed: {e}")
            return "Outbound"  # Default to Outbound instead of Unknown
    
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
    
    async def _create_complete_connection_established_event(self, conn, conn_info: Dict):
        """✅ ENHANCED: EVENT TYPE 1 - Connection Established Event with ALL required fields"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create connection event - missing agent_id")
                return None
            
            # ✅ ENHANCED: Extract ALL required network fields
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            destination_port = conn.raddr.port if conn.raddr else 0
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = self._determine_connection_direction(conn)
            
            # ✅ FIXED: Debug logging for direction determination
            self.logger.debug(f"🔍 Direction Debug: {source_ip}:{source_port} -> {destination_ip}:{destination_port} = {direction}")
            
            # Get process information
            process_name = conn_info.get('process_name', 'Unknown')
            process_id = conn.pid if conn.pid else None
            
            # Determine severity
            is_external = self._is_external_ip(destination_ip) if destination_ip != "0.0.0.0" else False
            is_suspicious = conn_info.get('is_suspicious', False)
            
            if is_suspicious:
                severity = "High"
            elif is_external:
                severity = "Medium"
            else:
                severity = "Info"
            
            # ✅ ENHANCED: Create comprehensive event with ALL fields
            event = EventData(
                event_type="Network",
                event_action="Connect",
                severity=severity,
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                # ✅ ENHANCED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD - FIXED
                
                # Process information
                process_id=process_id,
                process_name=process_name,
                
                description=f"🔗 LINUX CONNECTION ESTABLISHED: {source_ip}:{source_port} -> {destination_ip}:{destination_port} ({protocol}) | Process: {process_name} | Direction: {direction}",
                
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'connection_established',
                    'connection_info': conn_info,
                    'service_name': conn_info.get('service_name', 'Unknown'),
                    'is_well_known_port': conn_info.get('is_well_known_port', False),
                    'is_suspicious': is_suspicious,
                    'is_external': is_external,
                    'connection_direction': direction,
                    'monitoring_method': 'psutil_net_connections_complete',
                    'connection_status': conn.status if hasattr(conn, 'status') else 'Unknown',
                    'data_complete': True,
                    'local_address': f"{source_ip}:{source_port}",
                    'remote_address': f"{destination_ip}:{destination_port}",
                    'connection_family': conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                    'connection_type': conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                    'is_listening': conn.status == psutil.CONN_LISTEN,
                    'is_established': conn.status == psutil.CONN_ESTABLISHED,
                    'is_localhost': destination_ip in ['127.0.0.1', '::1'],
                    'timestamp': time.time()
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid connection event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Complete connection established event failed: {e}")
            return None
    
    async def _create_complete_connection_closed_event(self, conn_key: str, conn):
        """✅ ENHANCED: EVENT TYPE 5 - Connection Closed Event with ALL required fields"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create connection closed event - missing agent_id")
                return None
            
            # Parse connection key to extract details
            parts = conn_key.split('-')
            if len(parts) >= 2:
                local_part = parts[0]
                remote_part = parts[1]
                
                # Extract local address
                if ':' in local_part:
                    source_ip, source_port_str = local_part.rsplit(':', 1)
                    source_port = int(source_port_str) if source_port_str.isdigit() else 0
                else:
                    source_ip, source_port = "0.0.0.0", 0
                
                # Extract remote address
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
            
            protocol = 'TCP' if hasattr(conn, 'type') and conn.type == socket.SOCK_STREAM else 'TCP'
            
            # ✅ ENHANCED: Create network event with ALL required fields populated
            event = EventData(
                event_type="Network",
                event_action="Disconnect",
                event_timestamp=datetime.now(),
                severity="Info",
                agent_id=self.agent_id,
                
                # ✅ ENHANCED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                description=f"🔌 LINUX CONNECTION CLOSED: {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
                
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'connection_closed',
                    'connection_key': conn_key,
                    'close_time': time.time(),
                    'data_complete': True,
                    'local_address': f"{source_ip}:{source_port}",
                    'remote_address': f"{destination_ip}:{destination_port}",
                    'was_established': True,
                    'monitoring_method': 'connection_tracking_complete'
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid connection closed event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Complete connection closed event failed: {e}")
            return None
    
    async def _create_complete_suspicious_connection_event(self, conn, conn_info: Dict):
        """✅ ENHANCED: EVENT TYPE 2 - Suspicious Connection Event with ALL required fields"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create suspicious connection event - missing agent_id")
                return None
            
            # ✅ ENHANCED: Extract ALL required network fields
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            destination_port = conn.raddr.port if conn.raddr else 0
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = self._determine_connection_direction(conn)
            
            # ✅ ENHANCED: Create network event with ALL required fields populated
            event = EventData(
                event_type="Network",
                event_action="Suspicious",
                event_timestamp=datetime.now(),
                severity="High",
                agent_id=self.agent_id,
                
                # ✅ ENHANCED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                process_id=conn.pid,
                process_name=conn_info.get('process_name'),
                
                description=f"🚨 LINUX SUSPICIOUS CONNECTION: {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
                
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'suspicious_connection',
                    'suspicion_reason': 'suspicious_port_or_pattern',
                    'risk_level': 'high',
                    'connection_info': conn_info,
                    'service_name': conn_info.get('service_name', 'Unknown'),
                    'data_complete': True,
                    'monitoring_method': 'connection_analysis_complete'
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid suspicious connection event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Complete suspicious connection event failed: {e}")
            return None
    
    async def _create_complete_external_connection_event(self, conn, conn_info: Dict):
        """✅ ENHANCED: EVENT TYPE 3 - External Connection Event with ALL required fields"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create external connection event - missing agent_id")
                return None
            
            # ✅ ENHANCED: Extract ALL required network fields
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
            destination_port = conn.raddr.port if conn.raddr else 0
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = "Outbound"  # External connections are typically outbound
            
            # ✅ ENHANCED: Create network event with ALL required fields populated
            event = EventData(
                event_type="Network",
                event_action="Connect",
                event_timestamp=datetime.now(),
                severity="Info",
                agent_id=self.agent_id,
                
                # ✅ ENHANCED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD
                destination_port=destination_port,      # REQUIRED FIELD
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                process_id=conn.pid,
                process_name=conn_info.get('process_name'),
                
                description=f"🌐 LINUX EXTERNAL CONNECTION: {source_ip}:{source_port} -> {destination_ip}:{destination_port}",
                
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'external_connection',
                    'connection_type': 'outbound_external',
                    'destination_classification': 'external_ip',
                    'connection_info': conn_info,
                    'service_name': conn_info.get('service_name', 'Unknown'),
                    'data_complete': True,
                    'monitoring_method': 'external_ip_detection_complete'
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid external connection event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Complete external connection event failed: {e}")
            return None
    
    async def _create_complete_listening_port_event(self, conn, conn_info: Dict):
        """✅ ENHANCED: EVENT TYPE 4 - Listening Port Event with ALL required fields"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create listening port event - missing agent_id")
                return None
            
            # ✅ ENHANCED: Extract ALL required network fields for listening port
            source_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
            source_port = conn.laddr.port if conn.laddr else 0
            destination_ip = "0.0.0.0"  # Listening ports don't have destinations
            destination_port = 0        # Listening ports don't have destination ports
            protocol = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
            direction = "Listening"
            
            # ✅ ENHANCED: Create network event with ALL required fields populated
            event = EventData(
                event_type="Network",
                event_action="Access",
                event_timestamp=datetime.now(),
                severity="Medium" if source_port in self.suspicious_ports else "Info",
                agent_id=self.agent_id,
                
                # ✅ ENHANCED: ALWAYS populate ALL network-specific fields
                source_ip=source_ip,                    # REQUIRED FIELD
                source_port=source_port,                # REQUIRED FIELD
                destination_ip=destination_ip,          # REQUIRED FIELD (0.0.0.0 for listening)
                destination_port=destination_port,      # REQUIRED FIELD (0 for listening)
                protocol=protocol,                      # REQUIRED FIELD
                direction=direction,                    # REQUIRED FIELD
                
                process_id=conn.pid,
                process_name=conn_info.get('process_name'),
                
                description=f"🔌 LINUX LISTENING PORT: {source_ip}:{source_port} ({protocol})",
                
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'listening_port',
                    'port': source_port,
                    'service_name': conn_info.get('service_name', 'Unknown'),
                    'is_suspicious_port': source_port in self.suspicious_ports,
                    'connection_info': conn_info,
                    'data_complete': True,
                    'monitoring_method': 'listening_port_detection_complete'
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid listening port event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Complete listening port event failed: {e}")
            return None
    
    async def _create_complete_network_summary_event(self):
        """✅ ENHANCED: EVENT TYPE 6 - Network Summary Event with ALL required fields"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create network summary event - missing agent_id")
                return None
            
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
            
            # ✅ ENHANCED: Create network event with ALL required fields populated (using defaults for summary)
            event = EventData(
                event_type="Network",
                event_action="Resource_Usage",
                event_timestamp=datetime.now(),
                severity="Info",
                agent_id=self.agent_id,
                
                # ✅ ENHANCED: ALWAYS populate ALL network-specific fields (summary uses defaults)
                source_ip="0.0.0.0",                   # REQUIRED FIELD (summary event)
                source_port=0,                         # REQUIRED FIELD (summary event)
                destination_ip="0.0.0.0",              # REQUIRED FIELD (summary event)
                destination_port=0,                    # REQUIRED FIELD (summary event)
                protocol="Summary",                    # REQUIRED FIELD (summary event)
                direction="Summary",                   # REQUIRED FIELD (summary event)
                
                description=f"📊 LINUX NETWORK SUMMARY: {active_connections} active connections",
                
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
                    'data_complete': True,
                    'monitoring_method': 'network_summary_complete'
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid network summary event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Complete network summary event failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """✅ ENHANCED: Get detailed Linux network collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Enhanced_Linux_Network_CompleteData',
            'all_connection_events': self.stats['all_connection_events'],
            'connection_established_events': self.stats['connection_established_events'],
            'connection_closed_events': self.stats['connection_closed_events'],
            'listening_port_events': self.stats['listening_port_events'],
            'suspicious_connection_events': self.stats['suspicious_connection_events'],
            'external_connection_events': self.stats['external_connection_events'],
            'high_bandwidth_events': self.stats['high_bandwidth_events'],
            'port_scan_events': self.stats['port_scan_events'],
            'dns_query_events': self.stats['dns_query_events'],
            'network_summary_events': self.stats['network_summary_events'],
            'firewall_events': self.stats['firewall_events'],
            'total_network_events': self.stats['total_network_events'],
            'active_connections': len(self.monitored_connections),
            'port_activity_count': len(self.port_activity),
            'proc_net_available': self.proc_net_path.exists(),
            'monitor_tcp': self.monitor_tcp,
            'monitor_udp': self.monitor_udp,
            'suspicious_ports_count': len(self.suspicious_ports),
            'common_services_count': len(self.common_services),
            'bandwidth_threshold_mb': self.bandwidth_threshold / (1024 * 1024),
            'rate_limit_per_minute': self.max_network_events_per_minute,
            'complete_data_collection': True,
            'all_fields_populated': True,
            'linux_network_monitoring': True,
            'enhancement_version': '2.1.0-CompleteData'
        })
        return base_stats
    
    # ✅ ENHANCED: Network event filtering methods
    
    def _check_network_rate_limit(self) -> bool:
        """✅ ENHANCED: Check if we're within network event rate limits"""
        current_time = time.time()
        
        # Reset counter every minute
        if current_time - self.last_network_reset >= 60:
            self.network_events_this_minute = 0
            self.last_network_reset = current_time
        
        if self.network_events_this_minute >= self.max_network_events_per_minute:
            return False
        
        return True
    
    def _increment_network_event_count(self):
        """✅ ENHANCED: Increment network event count for rate limiting"""
        self.network_events_this_minute += 1
    
    def _is_network_event_worth_sending(self, event_type: str, conn_info: Dict) -> bool:
        """✅ ENHANCED: Check if network event is worth sending (deduplication)"""
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
        """✅ ENHANCED: Check if network event type should be filtered based on configuration"""
        if event_type == 'disconnect' and self.exclude_disconnect_events:
            return True
        elif event_type == 'connect' and self.exclude_connect_events:
            return True
        elif event_type == 'listen' and self.exclude_listen_events:
            return True
        elif event_type == 'established' and self.exclude_established_events:
            return True
        
        return False

# ✅ ENHANCED: Backward compatibility alias
LinuxNetworkCollector = EnhancedLinuxNetworkCollector