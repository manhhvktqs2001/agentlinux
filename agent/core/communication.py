# agent/core/communication.py - FIXED Linux Communication
"""
Linux Server Communication - FIXED to handle registration properly
Enhanced error handling and agent ID management
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
    """Linux Server Communication - FIXED VERSION"""
    
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
        
        # FIXED: Registration tracking
        self.registered_agent_id = None
        self.registration_attempts = 0
        self.max_registration_attempts = 3
        
        self.logger.info("🐧 Linux Communication initialized - FIXED for database compatibility")
    
    async def initialize(self):
        """Initialize Linux communication with enhanced server detection"""
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
    
    async def register_agent(self, registration_data: AgentRegistrationData) -> Optional[Dict]:
        """Register Linux agent with EDR server - FIXED with better error handling"""
        try:
            if not self.working_server:
                self.logger.warning("⚠️ No server available for Linux agent registration")
                return None
            
            self.registration_attempts += 1
            if self.registration_attempts > self.max_registration_attempts:
                self.logger.error(f"❌ Max registration attempts ({self.max_registration_attempts}) exceeded")
                return None
            
            url = f"{self.base_url}/api/v1/agents/register"
            
            # FIXED: Create robust registration payload
            registration_payload = {
                # REQUIRED fields with validation
                'hostname': registration_data.hostname or 'unknown-linux-host',
                'ip_address': registration_data.ip_address or '127.0.0.1',
                'operating_system': registration_data.operating_system or 'Linux Unknown',
                'os_version': registration_data.os_version or platform.release(),
                'architecture': registration_data.architecture or platform.machine(),
                'agent_version': '2.1.0-Linux',
                
                # OPTIONAL fields
                'mac_address': registration_data.mac_address,
                'domain': registration_data.domain,
                'install_path': registration_data.install_path,
                
                # Default values for required fields
                'status': 'Active',
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'disk_usage': 0.0,
                'network_latency': 0,
                'monitoring_enabled': True,
                
                # Linux-specific metadata
                'platform': 'linux',
                'kernel_version': registration_data.kernel_version,
                'distribution': registration_data.distribution,
                'distribution_version': registration_data.distribution_version,
                'has_root_privileges': registration_data.has_root_privileges,
                'current_user': registration_data.current_user,
                'effective_user': registration_data.effective_user,
                'user_groups': registration_data.user_groups,
                'capabilities': registration_data.capabilities,
                
                # Registration metadata
                'registration_attempt': self.registration_attempts,
                'client_timestamp': datetime.now().isoformat()
            }
            
            self.logger.info(f"📡 Attempting Linux agent registration (attempt {self.registration_attempts})")
            self.logger.debug(f"📦 Registration payload: hostname={registration_payload['hostname']}, platform={registration_payload['platform']}")
            self.logger.info(f"🌐 Domain in registration payload: {registration_payload.get('domain', 'NOT_SET')}")
            
            response = await self._make_request_with_retry('POST', url, registration_payload)
            
            if response:
                if response.get('success') or response.get('agent_id'):
                    # Extract agent_id from response
                    agent_id = response.get('agent_id')
                    if agent_id:
                        self.registered_agent_id = agent_id
                        self.logger.info(f"✅ Linux agent registered successfully: {agent_id}")
                        return response
                    else:
                        self.logger.error(f"❌ Registration response missing agent_id: {response}")
                        return None
                else:
                    error_msg = response.get('error', 'Unknown registration error')
                    self.logger.error(f"❌ Linux agent registration failed: {error_msg}")
                    
                    # FIXED: Handle specific error cases
                    if 'agent already exists' in error_msg.lower():
                        # Try to extract existing agent_id if provided
                        existing_id = response.get('existing_agent_id')
                        if existing_id:
                            self.registered_agent_id = existing_id
                            self.logger.info(f"📋 Using existing agent_id: {existing_id}")
                            return {'success': True, 'agent_id': existing_id}
                    
                    return None
            else:
                self.logger.error(f"❌ No response from server during registration")
                return None
            
        except Exception as e:
            self.logger.error(f"❌ Linux agent registration error: {e}")
            return None
    
    async def submit_event(self, event_data: EventData) -> tuple[bool, Optional[Dict], Optional[str]]:
        """Submit event to server with enhanced validation and auto re-register if agent not found"""
        try:
            # FIXED: Enhanced agent_id validation
            if not event_data.agent_id:
                self.logger.error("❌ CRITICAL: Event missing agent_id - cannot submit to server")
                return False, None, "Event missing agent_id"
            # Test connection before sending
            if not await self.test_connection():
                self.logger.debug("📡 Server not connected - queuing event for later")
                # Add to offline queue if not too full
                if len(self.offline_events_queue) < self.max_offline_events:
                    self.offline_events_queue.append(event_data.to_dict())
                return False, None, "Server not connected - event queued"
            if self.offline_mode:
                return False, None, "Server offline"
            if not self.working_server:
                return False, None, "No working server"
            # FIXED: Use event's to_dict() method with validation
            payload = event_data.to_dict()
            self.logger.info(f"[DEBUG] Payload to send: {json.dumps(payload)[:500]}")
            if 'error' in payload:
                self.logger.error(f"[DEBUG] Payload error: {payload['error']}")
                return False, None, f"Event payload error: {payload['error']}"
            if not payload.get('agent_id'):
                self.logger.error("[DEBUG] Payload missing agent_id after conversion!")
                return False, None, "Event payload conversion failed - missing agent_id"
            # Send to server with better error handling
            url = f"{self.base_url}/api/v1/events/submit"
            response = await self._make_request_with_retry('POST', url, payload)
            self.logger.info(f"[DEBUG] Server response: {str(response)[:500]}")
            # --- BỔ SUNG: Nếu server trả về lỗi "Agent not found", tự động re-register ---
            if response and response.get('error') and 'agent not found' in response.get('error', '').lower():
                self.logger.warning("🔄 Agent not found - auto re-registering with server...")
                from agent.schemas.agent_data import AgentRegistrationData
                # Tạo lại registration_data từ event hoặc config
                registration_data = AgentRegistrationData(
                    hostname=payload.get('hostname', 'unknown-linux-host'),
                    ip_address=payload.get('ip_address', '127.0.0.1'),
                    operating_system=payload.get('operating_system', 'Linux Unknown'),
                    os_version=payload.get('os_version', ''),
                    architecture=payload.get('architecture', ''),
                    agent_version=payload.get('agent_version', '2.1.0-Linux')
                )
                reg_response = await self.register_agent(registration_data)
                if reg_response and reg_response.get('agent_id'):
                    # Cập nhật agent_id cho toàn bộ hệ thống nếu có thể
                    self.registered_agent_id = reg_response['agent_id']
                    event_data.agent_id = reg_response['agent_id']
                    payload['agent_id'] = reg_response['agent_id']
                    # Gửi lại event với agent_id mới
                    response = await self._make_request_with_retry('POST', url, payload)
                    self.logger.info("✅ Event resent after re-registration.")
                    self.logger.info(f"[DEBUG] Server response after re-registration: {str(response)[:500]}")
                else:
                    self.logger.error("❌ Auto re-registration failed.")
                    return False, None, "Auto re-registration failed"
            if response and response.get('success'):
                return True, response, None
            else:
                self.logger.error(f"[DEBUG] Event submission failed, response: {str(response)[:500]}")
                return False, response, response.get('error', 'Unknown error')
        except Exception as e:
            self.logger.error(f"❌ Exception in submit_event: {e}")
            return False, None, str(e)
    
    async def send_heartbeat(self, heartbeat_data: AgentHeartbeatData) -> Optional[Dict]:
        """Send Linux agent heartbeat to server with enhanced error handling"""
        try:
            if self.offline_mode:
                return {
                    'success': True, 
                    'message': 'Linux offline mode heartbeat',
                    'offline_mode': True,
                    'platform': 'linux'
                }
            
            url = f"{self.base_url}/api/v1/agents/heartbeat"
            
            # FIXED: Create heartbeat payload with agent identification
            payload = {
                'hostname': heartbeat_data.hostname or 'unknown-linux-host',
                'status': heartbeat_data.status,
                'cpu_usage': heartbeat_data.cpu_usage,
                'memory_usage': heartbeat_data.memory_usage,
                'disk_usage': heartbeat_data.disk_usage,
                'network_latency': heartbeat_data.network_latency,
                'platform': 'linux',
                'uptime': heartbeat_data.uptime,
                'load_average': heartbeat_data.load_average,
                'memory_details': heartbeat_data.memory_details,
                'disk_details': heartbeat_data.disk_details,
                'network_details': heartbeat_data.network_details,
                'active_processes': heartbeat_data.active_processes,
                'collector_status': heartbeat_data.collector_status,
                'events_collected': heartbeat_data.events_collected,
                'events_sent': heartbeat_data.events_sent,
                'events_failed': heartbeat_data.events_failed,
                'alerts_received': heartbeat_data.alerts_received,
                'security_status': heartbeat_data.security_status,
                'threat_level': heartbeat_data.threat_level,
                'agent_process_id': heartbeat_data.agent_process_id,
                'timestamp': heartbeat_data.timestamp,
                'metadata': heartbeat_data.metadata,
                
                # FIXED: Include agent identification
                'agent_id': heartbeat_data.agent_id or self.registered_agent_id,
                'heartbeat_sequence': int(time.time())  # Sequence number for tracking
            }
            
            # Add optional fields if present
            if hasattr(heartbeat_data, 'ip_address') and heartbeat_data.ip_address:
                payload['ip_address'] = heartbeat_data.ip_address
            if hasattr(heartbeat_data, 'operating_system') and heartbeat_data.operating_system:
                payload['operating_system'] = heartbeat_data.operating_system
            
            response = await self._make_request_with_retry('POST', url, payload)
            
            if response:
                # Check for agent registration issues in heartbeat response
                if response.get('error') and 'agent not found' in response.get('error', '').lower():
                    self.logger.warning("⚠️ Server reports agent not found - may need re-registration")
                    self.registered_agent_id = None  # Clear cached agent_id
                
                return response
            else:
                return {
                    'success': True, 
                    'message': 'Linux heartbeat sent (no response)',
                    'offline_mode': self.offline_mode,
                    'platform': 'linux'
                }
            
        except Exception as e:
            self.logger.debug(f"Heartbeat error: {e}")
            return {
                'success': True,
                'message': 'Linux offline mode heartbeat (error)',
                'offline_mode': True,
                'platform': 'linux'
            }
    
    async def _make_request_with_retry(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with retry logic and better error handling"""
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
                
                error_str = str(e).lower()
                if "cannot connect to host" in error_str or "connection refused" in error_str:
                    self._mark_as_offline("Linux server connection refused")
                    break
                elif "agent not found" in error_str:
                    self.logger.warning("⚠️ Server reports agent not found - clearing cached agent_id")
                    self.registered_agent_id = None
                    break
                
                if attempt < max_retries:
                    await asyncio.sleep(retry_delay)
        
        if not self.offline_mode:
            self._mark_as_offline("All Linux request attempts failed")
        
        return None
    
    async def _make_request_internal(self, method: str, url: str, payload: Optional[Dict] = None, 
                                   timeout_override: Optional[float] = None) -> Optional[Dict]:
        """Internal method to make HTTP request with enhanced error handling"""
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
        """Handle HTTP response with enhanced error handling"""
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
                    
            elif response.status == 400:
                try:
                    error_data = await response.json()
                    error_msg = error_data.get('error', 'Unknown error')
                    self.logger.warning(f"⚠️ LINUX CLIENT ERROR (400): {error_msg}")
                    
                    # FIXED: Handle "agent not found" specifically
                    if 'agent not found' in error_msg.lower():
                        self.logger.warning("🔄 Agent not found on server - may need re-registration")
                        self.registered_agent_id = None
                    
                    return error_data  # Return error data for handling
                except json.JSONDecodeError:
                    text = await response.text()
                    self.logger.warning(f"⚠️ LINUX CLIENT ERROR (400): {text}")
                    return {'error': text}
                    
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
    
    def _setup_offline_mode(self):
        """Setup offline mode with Linux-specific settings"""
        self.logger.info("🔄 Setting up Linux offline mode...")
        self.offline_events_queue = []
    
    def _mark_as_offline(self, reason: str = "Connection error"):
        """Immediately mark communication as offline"""
        if not self.offline_mode:
            self.logger.info(f"📡 Linux {reason} - entering offline mode")
            self.offline_mode = True
    
    async def _detect_working_server(self):
        """Auto-detect working EDR server - Linux optimized"""
        # Chỉ thử đúng IP backend bạn muốn
        potential_servers = [
            {'host': '192.168.20.85', 'port': 5000, 'name': 'Configured Server'},
        ]
        for server in potential_servers:
            if await self._test_server_connection(server):
                self.logger.info(f"✅ Found working server: {server['name']} ({server['host']}:{server['port']})")
                return server
        return None
    
    async def _test_server_connection(self, server):
        """Test connection to a specific server"""
        try:
            host = server['host']
            port = server['port']
            
            # Test TCP connection
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
    
    def _process_server_response(self, server_response: Dict[str, Any], original_event: EventData) -> Dict[str, Any]:
        """Process server response for threat detection"""
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
            
            return processed_response
                
        except Exception as e:
            self.logger.error(f"❌ Linux server response processing error: {e}")
            return {
                'success': True,
                'threat_detected': False,
                'risk_score': 0,
                'error': str(e)
            }
    
    async def close(self):
        """Close communication session"""
        try:
            if self.session and not self.session.closed:
                await self.session.close()
                self._session_closed = True
        except Exception as e:
            self.logger.error(f"Error closing Linux session: {e}")
    
    async def _periodic_server_detection(self):
        """Periodically check for server availability"""
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
                        if await self.test_connection():
                            self.logger.info("✅ Successfully reconnected to server!")
                            self.offline_mode = False
                            # Optionally, send queued events here
                        else:
                            self.logger.debug("🔄 Reconnection failed - will try again")
                    await asyncio.sleep(1)
                else:
                    # If online, check connection every 15 seconds
                    await asyncio.sleep(15)
                    if not await self.test_connection():
                        self.logger.warning("⚠️ Lost connection to server - entering offline mode")
                        self.offline_mode = True
            except Exception as e:
                self.logger.debug(f"Periodic server detection error: {e}")
                await asyncio.sleep(3)
    
    def is_connected(self) -> bool:
        """Return True if communication is online and a working server is set"""
        return not self.offline_mode and self.working_server is not None

# Alias for compatibility with existing code
ServerCommunication = LinuxServerCommunication