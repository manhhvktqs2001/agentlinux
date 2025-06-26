# agent/core/communication.py - FIXED Linux Communication
"""
Linux Server Communication - FIXED TO MATCH DATABASE SCHEMA
Handle communication with EDR server with proper payload format
"""

import aiohttp
import asyncio
import logging
import json
import time
import socket
import requests
from typing import Optional, Dict, List, Any
from datetime import datetime
import platform

from agent.core.config_manager import ConfigManager
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from agent.schemas.events import EventData

class LinuxServerCommunication:
    """Linux Server Communication - FIXED FOR DATABASE COMPATIBILITY"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.server_config = self.config.get('server', {})
        
        # Auto-detect working server
        self.working_server = None
        self.server_host = None
        self.server_port = None
        self.base_url = None
        self.offline_mode = False
        
        # Authentication
        self.auth_token = self.server_config.get('auth_token', 'edr_agent_auth_2024')
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        self._session_closed = False
        
        # Linux-optimized timeout settings
        self.timeout = 5
        self.connect_timeout = 3
        self.read_timeout = 5
        self.max_retries = 2
        self.retry_delay = 1.0
        
        # Connection pooling
        self.connection_pool_size = 10
        self.keep_alive_timeout = 30
        self.total_timeout = 10
        
        # Performance tracking
        self.connection_attempts = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.last_successful_connection = None
        
        # Offline mode support
        self.offline_events_queue = []
        self.max_offline_events = 2000
        
        # Server response tracking
        self.threats_detected_by_server = 0
        self.alerts_received_from_server = 0
        self.last_threat_detection = None
        
        self.logger.info("🐧 Linux Communication initialized - FIXED for database compatibility")
    
    async def initialize(self):
        """Initialize Linux communication with server detection"""
        try:
            # Auto-detect working server
            self.working_server = await self._detect_working_server()
            
            if not self.working_server:
                self.logger.warning("⚠️ No EDR server found - enabling offline mode")
                self.offline_mode = True
                self._setup_offline_mode()
                return
            
            # Set server details
            self.server_host = self.working_server['host']
            self.server_port = self.working_server['port']
            self.base_url = f"http://{self.server_host}:{self.server_port}"
            self.offline_mode = False
            
            # Close existing session if any
            await self.close()
            
            # Setup Linux-optimized timeout configuration
            timeout = aiohttp.ClientTimeout(
                total=self.total_timeout,
                connect=self.connect_timeout,
                sock_read=self.read_timeout,
                sock_connect=self.connect_timeout
            )
            
            # Setup headers with Linux identification
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.auth_token,
                'User-Agent': 'EDR-Agent/2.1.0-Linux',
                'X-Platform': 'Linux',
                'Connection': 'keep-alive',
                'Accept': 'application/json'
            }
            
            # Setup connector
            connector = aiohttp.TCPConnector(
                limit=self.connection_pool_size,
                limit_per_host=self.connection_pool_size,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=self.keep_alive_timeout,
                enable_cleanup_closed=True,
                force_close=False,
                ssl=False
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector,
                raise_for_status=False
            )
            self._session_closed = False
            
            # Test connection
            connection_ok = await self._test_connection()
            
            if connection_ok:
                self.logger.info(f"✅ Linux communication initialized successfully: {self.base_url}")
            else:
                self.logger.warning(f"⚠️ Server detected but not responding: {self.base_url}")
                self.offline_mode = True
                self._setup_offline_mode()
            
            # Start periodic server detection task
            if not hasattr(self, '_periodic_task_started'):
                self._periodic_task_started = True
                asyncio.create_task(self._periodic_server_detection())
                self.logger.info("🔄 Periodic server detection task started")
            
        except Exception as e:
            self.logger.error(f"❌ Linux communication initialization failed: {e}")
            self.offline_mode = True
            self._setup_offline_mode()
    
    def _setup_offline_mode(self):
        """Setup offline mode with Linux-specific settings"""
        self.logger.info("🔄 Setting up Linux offline mode...")
        self.offline_events_queue = []
        
        # Only start periodic detection task if not already started
        if not hasattr(self, '_periodic_task_started'):
            self._periodic_task_started = True
            asyncio.create_task(self._periodic_server_detection())
            self.logger.info("🔄 Periodic server detection task started")
    
    async def _periodic_server_detection(self):
        """Periodically check for server availability - Linux optimized"""
        last_reconnection_attempt = 0
        reconnection_interval = 3  # Try every 3 seconds when offline
        
        while True:
            try:
                current_time = time.time()
                
                # If offline, continuously try to reconnect
                if self.offline_mode:
                    if current_time - last_reconnection_attempt >= reconnection_interval:
                        self.logger.debug("🔄 Attempting to reconnect to server...")
                        last_reconnection_attempt = current_time
                        
                        if await self.force_reconnection():
                            self.logger.info("✅ Successfully reconnected to server!")
                            await self._send_queued_events()
                        else:
                            self.logger.debug("📡 Reconnection failed - will try again")
                    
                    await asyncio.sleep(1)
                
                # If online, check connection every 15 seconds
                else:
                    await self._detect_connection_loss()
                    await asyncio.sleep(15)
                    
            except Exception as e:
                self.logger.debug(f"Periodic server detection error: {e}")
                await asyncio.sleep(3)
    
    async def _send_queued_events(self):
        """Send queued offline events"""
        if not self.offline_events_queue:
            return
        
        self.logger.info(f"📤 Sending {len(self.offline_events_queue)} queued events...")
        events_to_send = self.offline_events_queue.copy()
        self.offline_events_queue.clear()
        sent_count = 0
        
        for event_data in events_to_send:
            try:
                response = await self._make_request_with_retry('POST', f"{self.base_url}/api/v1/events/submit", event_data)
                if response:
                    sent_count += 1
                else:
                    self.offline_events_queue.append(event_data)
            except:
                self.offline_events_queue.append(event_data)
        
        self.logger.info(f"✅ Sent {sent_count}/{len(events_to_send)} queued events")
    
    async def _detect_working_server(self):
        """Auto-detect working EDR server - Linux optimized"""
        potential_servers = [
            {'host': 'localhost', 'port': 5000, 'name': 'Local Server'},
            {'host': '127.0.0.1', 'port': 5000, 'name': 'Loopback Server'},
            {'host': '192.168.20.85', 'port': 5000, 'name': 'Configured Server'},
            {'host': 'localhost', 'port': 8000, 'name': 'Alt Port 8000'},
            {'host': '127.0.0.1', 'port': 3000, 'name': 'Alt Port 3000'},
        ]
        
        for server in potential_servers:
            if await self._test_server_connection(server):
                self.logger.info(f"✅ Found working server: {server['name']} ({server['host']}:{server['port']})")
                return server
        
        return None
    
    async def _test_server_connection(self, server):
        """Test connection to a specific server - Linux optimized"""
        try:
            host = server['host']
            port = server['port']
            
            # Test TCP connection with Linux socket
            def test_tcp():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
                except:
                    return False
            
            tcp_success = await asyncio.to_thread(test_tcp)
            return tcp_success
            
        except Exception as e:
            return False
    
    async def _test_connection(self):
        """Test connection to selected server"""
        try:
            if not self.working_server:
                return False
            
            test_endpoints = ['/health', '/api/v1/status', '/', '/status']
            
            for endpoint in test_endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    response = await self._make_request_internal('GET', url, timeout_override=5)
                    
                    if response is not None:
                        self.last_successful_connection = time.time()
                        self.successful_connections += 1
                        return True
                except:
                    continue
            
            return False
            
        except Exception as e:
            return False
    
    async def submit_event(self, event_data: EventData) -> tuple[bool, Optional[Dict], Optional[str]]:
        """
        FIXED: Submit event to server with database-compatible payload
        """
        try:
            # Test connection before sending
            if not await self.test_connection():
                self.logger.debug("📡 Server not connected - skipping event submission")
                return False, None, "Server not connected"
            
            if self.offline_mode:
                return False, None, "Server offline"
            
            if not self.working_server:
                return False, None, "No working server"
            
            # FIXED: Convert event to database-compatible payload
            payload = self._convert_event_to_database_payload(event_data)
            
            if payload is None:
                return False, None, "Event payload conversion failed - missing agent_id"
            
            # Send to server
            url = f"{self.base_url}/api/v1/events/submit"
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response:
                # Update last successful connection time
                self.last_successful_connection = time.time()
                
                # Process server response for threat detection
                processed_response = self._process_server_response(response, event_data)
                return True, processed_response, None
            else:
                self.logger.debug("📡 No response from server - marking as disconnected")
                return False, None, "No response from server"
                
        except Exception as e:
            return False, None, str(e)
    
    def _convert_event_to_database_payload(self, event_data: EventData) -> Optional[Dict]:
        """
        FIXED: Convert event data to database-compatible API payload
        Maps EventData fields to database schema exactly
        """
        try:
            # Validate agent_id is present
            if not event_data.agent_id:
                self.logger.error(f"❌ CRITICAL: Linux event missing agent_id - Type: {event_data.event_type}, Action: {event_data.event_action}")
                return None
            
            # FIXED: Create payload matching database schema exactly
            payload = {
                # REQUIRED FIELDS (matching Events table)
                'AgentID': event_data.agent_id,
                'EventType': event_data.event_type,  # Process, File, Network, Registry, Authentication, System
                'EventAction': event_data.event_action,  # String value, not enum
                'EventTimestamp': event_data.event_timestamp.isoformat(),
                'Severity': event_data.severity,  # Info, Low, Medium, High, Critical
                
                # Process fields (optional)
                'ProcessID': event_data.process_id,
                'ProcessName': event_data.process_name,
                'ProcessPath': event_data.process_path,
                'CommandLine': event_data.command_line,
                'ParentPID': event_data.parent_pid,
                'ParentProcessName': event_data.parent_process_name,
                'ProcessUser': event_data.process_user,
                'ProcessHash': event_data.process_hash,
                
                # File fields (optional)
                'FilePath': event_data.file_path,
                'FileName': event_data.file_name,
                'FileSize': event_data.file_size,
                'FileHash': event_data.file_hash,
                'FileExtension': event_data.file_extension,
                'FileOperation': event_data.file_operation,
                
                # Network fields (optional)
                'SourceIP': event_data.source_ip,
                'DestinationIP': event_data.destination_ip,
                'SourcePort': event_data.source_port,
                'DestinationPort': event_data.destination_port,
                'Protocol': event_data.protocol,
                'Direction': event_data.direction,
                
                # Registry fields (optional, for compatibility)
                'RegistryKey': event_data.registry_key,
                'RegistryValueName': event_data.registry_value_name,
                'RegistryValueData': event_data.registry_value_data,
                'RegistryOperation': event_data.registry_operation,
                
                # Authentication fields (optional)
                'LoginUser': event_data.login_user,
                'LoginType': event_data.login_type,
                'LoginResult': event_data.login_result,
                
                # Detection status fields
                'ThreatLevel': event_data.threat_level,  # None, Suspicious, Malicious
                'RiskScore': event_data.risk_score,  # 0-100
                'Analyzed': event_data.analyzed,
                'AnalyzedAt': event_data.analyzed_at.isoformat() if event_data.analyzed_at else None,
                
                # Raw event data (JSON string)
                'RawEventData': event_data.raw_event_data
            }
            
            # Remove None values to match database requirements
            cleaned_payload = {}
            for key, value in payload.items():
                if value is not None:
                    cleaned_payload[key] = value
            
            # Ensure we have minimum required fields
            required_fields = ['AgentID', 'EventType', 'EventAction', 'EventTimestamp', 'Severity']
            for field in required_fields:
                if field not in cleaned_payload:
                    self.logger.error(f"❌ Missing required field in payload: {field}")
                    return None
            
            self.logger.debug(f"📦 LINUX DATABASE PAYLOAD CREATED:")
            self.logger.debug(f"   🎯 Type: {cleaned_payload.get('EventType')}")
            self.logger.debug(f"   🔧 Action: {cleaned_payload.get('EventAction')}")
            self.logger.debug(f"   📊 Severity: {cleaned_payload.get('Severity')}")
            self.logger.debug(f"   🆔 Agent ID: {cleaned_payload.get('AgentID')}")
            
            return cleaned_payload
            
        except Exception as e:
            self.logger.error(f"❌ Linux event payload conversion failed: {e}")
            return None
    
    def _process_server_response(self, server_response: Dict[str, Any], original_event: EventData) -> Dict[str, Any]:
        """Process server response for threat detection - Linux specific"""
        try:
            if not server_response:
                return {'success': False, 'threat_detected': False, 'risk_score': 0}
            
            # Initialize processed response
            processed_response = server_response.copy()
            
            # Ensure required fields
            if 'threat_detected' not in processed_response:
                processed_response['threat_detected'] = False
            if 'risk_score' not in processed_response:
                processed_response['risk_score'] = 0
            
            # CASE 1: Server detected threat
            if server_response.get('threat_detected', False):
                self.threats_detected_by_server += 1
                self.last_threat_detection = datetime.now()
                
                self.logger.warning(f"🚨 LINUX SERVER DETECTED THREAT: {original_event.event_type} - Risk: {server_response.get('risk_score', 0)}")
                
                # Ensure complete threat information
                if 'rule_triggered' not in processed_response:
                    processed_response['rule_triggered'] = 'Linux Server Threat Detection'
                if 'threat_description' not in processed_response:
                    processed_response['threat_description'] = f'Suspicious Linux {original_event.event_type} activity detected'
                
                return processed_response
            
            # CASE 2: Server generated alerts
            if 'alerts_generated' in server_response and server_response['alerts_generated']:
                alerts = server_response['alerts_generated']
                self.alerts_received_from_server += len(alerts)
                self.last_threat_detection = datetime.now()
                
                self.logger.warning(f"🚨 LINUX SERVER GENERATED {len(alerts)} ALERTS for {original_event.event_type}")
                
                processed_response['threat_detected'] = True
                if not processed_response.get('risk_score'):
                    max_risk = max((alert.get('risk_score', 50) for alert in alerts), default=50)
                    processed_response['risk_score'] = max_risk
                
                return processed_response
            
            # CASE 3: High risk score
            risk_score = server_response.get('risk_score', 0)
            if risk_score >= 70:
                self.threats_detected_by_server += 1
                self.last_threat_detection = datetime.now()
                
                self.logger.warning(f"🚨 LINUX HIGH RISK SCORE: {risk_score} for {original_event.event_type}")
                
                processed_response['threat_detected'] = True
                processed_response['rule_triggered'] = 'Linux High Risk Score Detection'
                processed_response['threat_description'] = f'High risk Linux {original_event.event_type} activity (Score: {risk_score})'
                
                return processed_response
            
            # CASE 4: Normal processing
            self.logger.debug(f"✅ Linux server processed {original_event.event_type} normally - no threats detected")
            processed_response['threat_detected'] = False
            
            return processed_response
            
        except Exception as e:
            self.logger.error(f"❌ Linux server response processing error: {e}")
            return {
                'success': True,
                'threat_detected': False,
                'risk_score': 0,
                'error': str(e)
            }
    
    async def _make_request_with_retry(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retry logic - Linux optimized"""
        if self.offline_mode and '/health' not in url and '/status' not in url:
            return None
        
        max_retries = 1 if self.offline_mode else self.max_retries
        retry_delay = 0.5 if self.offline_mode else self.retry_delay
        
        for attempt in range(max_retries + 1):
            try:
                self.connection_attempts += 1
                response = await self._make_request_internal(method, url, payload)
                
                if response is not None:
                    self.successful_connections += 1
                    self.last_successful_connection = time.time()
                    return response
                
            except Exception as e:
                self.failed_connections += 1
                
                if "Cannot connect to host" in str(e) or "Connection refused" in str(e):
                    self._mark_as_offline("Linux server connection refused")
                    break
                
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay)
        
        if not self.offline_mode:
            self._mark_as_offline("All Linux request attempts failed")
        
        return None
    
    async def _make_request_internal(self, method: str, url: str, payload: Optional[Dict] = None, 
                                   timeout_override: Optional[float] = None) -> Optional[Dict]:
        """Internal method to make HTTP request"""
        if (self.offline_mode and '/health' not in url and '/status' not in url) or not self.session or self._session_closed:
            return None
        
        try:
            if timeout_override:
                timeout = aiohttp.ClientTimeout(total=timeout_override)
            elif self.offline_mode:
                timeout = aiohttp.ClientTimeout(total=5, connect=2, sock_read=3)
            else:
                timeout = None
            
            self.logger.debug(f"🐧 LINUX HTTP {method} REQUEST: {url}")
            if payload:
                self.logger.debug(f"📦 PAYLOAD SIZE: {len(str(payload))} chars")
            
            if method.upper() == 'GET':
                async with self.session.get(url, timeout=timeout) as response:
                    self.logger.debug(f"📡 LINUX HTTP RESPONSE: {response.status} - {url}")
                    return await self._handle_response(response)
                    
            elif method.upper() == 'POST':
                async with self.session.post(url, json=payload, timeout=timeout) as response:
                    self.logger.debug(f"📡 LINUX HTTP RESPONSE: {response.status} - {url}")
                    return await self._handle_response(response)
                    
            else:
                raise Exception(f"Unsupported HTTP method: {method}")
                
        except asyncio.TimeoutError:
            self.logger.error(f"⏰ LINUX REQUEST TIMEOUT: {url}")
            raise asyncio.TimeoutError(f"Linux request timeout: {url}")
        except Exception as e:
            self.logger.error(f"❌ LINUX REQUEST ERROR: {url} - {e}")
            raise Exception(f"Linux request error: {e}")
    
    async def _handle_response(self, response: aiohttp.ClientResponse) -> Optional[Dict]:
        """Handle HTTP response"""
        try:
            self.logger.debug(f"📥 LINUX RESPONSE: Status={response.status}, Content-Type={response.headers.get('content-type', 'unknown')}")
            
            if response.status == 200:
                try:
                    data = await response.json()
                    self.logger.debug(f"✅ LINUX JSON RESPONSE: {len(str(data))} chars")
                    return data
                except json.JSONDecodeError:
                    text = await response.text()
                    self.logger.debug(f"📄 LINUX TEXT RESPONSE: {len(text)} chars")
                    if len(text) < 200:
                        return {'success': True, 'message': text}
                    return None
                    
            elif response.status == 422:
                try:
                    error_data = await response.json()
                    self.logger.error(f"❌ LINUX VALIDATION ERROR (422): {error_data}")
                    return None
                except json.JSONDecodeError:
                    text = await response.text()
                    self.logger.error(f"❌ LINUX VALIDATION ERROR (422): {text}")
                    return None
                    
            elif response.status in [404, 405]:
                self.logger.error(f"❌ LINUX ENDPOINT NOT FOUND: {response.status} - {response.url}")
                return None
            elif response.status >= 500:
                text = await response.text()
                self.logger.error(f"❌ LINUX SERVER ERROR: {response.status} - {text[:200]}")
                raise Exception(f"Linux server error {response.status}: {text}")
            else:
                text = await response.text()
                self.logger.warning(f"⚠️ LINUX UNEXPECTED STATUS: {response.status} - {text[:200]}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Linux response handling error: {e}")
            return None
    
    async def register_agent(self, registration_data: AgentRegistrationData) -> Optional[Dict]:
        """Register Linux agent with EDR server - FIXED for database"""
        try:
            if not self.working_server:
                self.logger.warning("⚠️ No server available for Linux agent registration")
                return None
            
            url = f"{self.base_url}/api/v1/agents/register"
            
            # FIXED: Create registration payload matching database schema
            registration_payload = {
                # REQUIRED fields matching Agents table
                'HostName': registration_data.hostname,
                'IPAddress': registration_data.ip_address,
                'OperatingSystem': registration_data.operating_system,
                'OSVersion': registration_data.os_version or platform.release(),
                'Architecture': registration_data.architecture or platform.machine(),
                'AgentVersion': '2.1.0-Linux',
                
                # OPTIONAL fields
                'MACAddress': registration_data.mac_address,
                'Domain': registration_data.domain,
                'InstallPath': registration_data.install_path,
                
                # Default values for required fields
                'Status': 'Active',
                'CPUUsage': 0.0,
                'MemoryUsage': 0.0,
                'DiskUsage': 0.0,
                'NetworkLatency': 0,
                'MonitoringEnabled': True,
                
                # Linux-specific metadata
                'Platform': 'linux',
                'KernelVersion': registration_data.kernel_version,
                'Distribution': registration_data.distribution,
                'DistributionVersion': registration_data.distribution_version,
                'HasRootPrivileges': registration_data.has_root_privileges,
                'CurrentUser': registration_data.current_user,
                'EffectiveUser': registration_data.effective_user,
                'UserGroups': registration_data.user_groups,
                'Capabilities': registration_data.capabilities
            }
            
            response = await self._make_request_with_retry('POST', url, registration_payload)
            
            if response and response.get('agent_id'):
                self.logger.info(f"✅ Linux agent registered successfully: {response['agent_id']}")
                return response
            else:
                self.logger.error(f"❌ Linux agent registration failed: {response}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Linux agent registration error: {e}")
            return None
    
    async def send_heartbeat(self, heartbeat_data: AgentHeartbeatData) -> Optional[Dict]:
        """Send Linux agent heartbeat to server - FIXED for database"""
        try:
            if self.offline_mode:
                return {
                    'success': True, 
                    'message': 'Linux offline mode heartbeat',
                    'offline_mode': True,
                    'platform': 'linux'
                }
            
            url = f"{self.base_url}/api/v1/agents/heartbeat"
            
            # FIXED: Create heartbeat payload matching database expectations
            payload = {
                'Status': heartbeat_data.status,
                'CPUUsage': heartbeat_data.cpu_usage,
                'MemoryUsage': heartbeat_data.memory_usage,
                'DiskUsage': heartbeat_data.disk_usage,
                'NetworkLatency': heartbeat_data.network_latency,
                'Platform': 'linux',
                'Uptime': heartbeat_data.uptime,
                'LoadAverage': heartbeat_data.load_average,
                'MemoryDetails': heartbeat_data.memory_details,
                'DiskDetails': heartbeat_data.disk_details,
                'NetworkDetails': heartbeat_data.network_details,
                'ActiveProcesses': heartbeat_data.active_processes,
                'CollectorStatus': heartbeat_data.collector_status,
                'EventsCollected': heartbeat_data.events_collected,
                'EventsSent': heartbeat_data.events_sent,
                'EventsFailed': heartbeat_data.events_failed,
                'AlertsReceived': heartbeat_data.alerts_received,
                'SecurityStatus': heartbeat_data.security_status,
                'ThreatLevel': heartbeat_data.threat_level
            }
            
            response = await self._make_request_with_retry('POST', url, payload)
            return response or {
                'success': True, 
                'message': 'Linux heartbeat sent (no response)',
                'offline_mode': self.offline_mode,
                'platform': 'linux'
            }
            
        except Exception as e:
            return {
                'success': True, 
                'message': 'Linux offline mode heartbeat (error)',
                'offline_mode': True,
                'platform': 'linux'
            }
    
    async def close(self):
        """Close communication session"""
        try:
            if self.session and not self._session_closed:
                await self.session.close()
                self._session_closed = True
        except Exception as e:
            self.logger.error(f"Error closing Linux session: {e}")
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get Linux server connection information"""
        return {
            'working_server': self.working_server,
            'host': self.server_host,
            'port': self.server_port,
            'base_url': self.base_url,
            'offline_mode': self.offline_mode,
            'timeout': self.timeout,
            'connection_attempts': self.connection_attempts,
            'successful_connections': self.successful_connections,
            'failed_connections': self.failed_connections,
            'last_successful_connection': self.last_successful_connection,
            'session_active': self.session is not None and not self._session_closed,
            'success_rate': (self.successful_connections / max(self.connection_attempts, 1)) * 100 if self.connection_attempts > 0 else 0,
            'offline_events_queued': len(self.offline_events_queue),
            'max_offline_events': self.max_offline_events,
            'threats_detected_by_server': self.threats_detected_by_server,
            'alerts_received_from_server': self.alerts_received_from_server,
            'last_threat_detection': self.last_threat_detection.isoformat() if self.last_threat_detection else None,
            'platform': 'linux',
            'database_compatible': True,
            'fixed_payload_format': True
        }
    
    def is_connected(self) -> bool:
        """Check if Linux server is connected and responding"""
        try:
            if not self.working_server or self.offline_mode:
                return False
            
            if not self.session or self._session_closed:
                self.offline_mode = True
                return False
            
            if self.last_successful_connection:
                time_since_last_success = time.time() - self.last_successful_connection
                if time_since_last_success < 20:  # 20 seconds for Linux
                    return True
                else:
                    self.offline_mode = True
                    return False
            
            self.offline_mode = True
            return False
            
        except Exception:
            self.offline_mode = True
            return False
    
    async def test_connection(self) -> bool:
        """Test actual connection to server"""
        try:
            if not self.working_server:
                self.logger.debug("📡 No working server configured")
                return False
            
            self.logger.debug(f"📡 Testing Linux HTTP connection to: {self.base_url}/health")
            
            response = await self._make_request_with_retry('GET', f"{self.base_url}/health")
            if response:
                self.last_successful_connection = time.time()
                self.logger.debug("📡 Linux HTTP connection test successful")
                return True
            else:
                self.logger.debug("📡 Linux HTTP connection test failed - no response")
                return False
            
        except Exception as e:
            self.logger.debug(f"📡 Linux HTTP connection test error: {e}")
            return False
    
    async def force_reconnection(self) -> bool:
        """Force reconnection attempt for Linux"""
        try:
            self.logger.debug("🔄 Linux force reconnection attempt...")
            
            self.last_successful_connection = None
            
            working_server = await self._detect_working_server()
            if working_server:
                self.working_server = working_server
                self.server_host = working_server['host']
                self.server_port = working_server['port']
                self.base_url = f"http://{self.server_host}:{self.server_port}"
                
                self.logger.debug(f"📡 Linux server detected: {self.base_url}")
                
                await self.close()
                
                timeout = aiohttp.ClientTimeout(
                    total=15,
                    connect=5,
                    sock_read=8,
                    sock_connect=5
                )
                
                headers = {
                    'Content-Type': 'application/json',
                    'X-Agent-Token': self.auth_token,
                    'User-Agent': 'EDR-Agent/2.1.0-Linux',
                    'X-Platform': 'Linux',
                    'Connection': 'keep-alive',
                    'Accept': 'application/json'
                }
                
                connector = aiohttp.TCPConnector(
                    limit=self.connection_pool_size,
                    limit_per_host=self.connection_pool_size,
                    ttl_dns_cache=300,
                    use_dns_cache=True,
                    keepalive_timeout=self.keep_alive_timeout,
                    enable_cleanup_closed=True,
                    force_close=False,
                    ssl=False
                )
                
                self.session = aiohttp.ClientSession(
                    timeout=timeout,
                    headers=headers,
                    connector=connector,
                    raise_for_status=False
                )
                self._session_closed = False
                
                self.logger.debug("📡 Linux session reinitialized, testing connection...")
                
                if await self.test_connection():
                    self.offline_mode = False
                    self.logger.info("✅ Linux force reconnection successful")
                    return True
                else:
                    self.logger.debug("📡 Linux force reconnection failed - HTTP test failed")
                    return False
            else:
                self.logger.debug("📡 Linux force reconnection failed - no server detected")
                return False
                
        except Exception as e:
            self.logger.debug(f"Linux force reconnection error: {e}")
            return False
    
    def _mark_as_offline(self, reason: str = "Connection error"):
        """Immediately mark communication as offline"""
        if not self.offline_mode:
            self.logger.info(f"📡 Linux {reason} - entering offline mode")
            self.offline_mode = True
    
    async def _detect_connection_loss(self):
        """Detect if Linux connection is lost"""
        try:
            if self.offline_mode:
                return
            
            if self.last_successful_connection:
                time_since_last_success = time.time() - self.last_successful_connection
                if time_since_last_success > 20:  # 20 seconds for Linux
                    self.logger.info("📡 Linux connection lost - entering offline mode")
                    self.offline_mode = True
                    return
            
            if not self.last_successful_connection and not self.offline_mode:
                self.logger.info("📡 No recent Linux connection - entering offline mode")
                self.offline_mode = True
                
        except Exception as e:
            self.logger.debug(f"Linux connection loss detection error: {e}")
            self.offline_mode = True

# Alias for compatibility
ServerCommunication = LinuxServerCommunication