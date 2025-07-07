# agent/core/communication.py - ENHANCED với Alert Processing
"""
ENHANCED Communication Manager với xử lý alerts từ server
Thêm khả năng nhận và xử lý security alerts từ EDR server
"""

import aiohttp
import asyncio
import logging
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import deque
from dataclasses import dataclass
from agent.core.config_manager import ConfigManager
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData, create_linux_registration_data
from agent.schemas.events import EventData
import redis
from agent.utils import process_utils
import subprocess
import os
import signal
import platform
import socket
from pathlib import Path

# ✅ ENHANCED: Security Alert Data Structure
@dataclass
class SecurityAlert:
    """Security Alert từ server"""
    alert_id: str
    agent_id: str
    alert_type: str
    severity: str
    risk_score: int
    title: str
    description: str
    rule_name: str
    rule_description: str
    threat_description: str
    event_details: Dict[str, Any]
    timestamp: datetime
    requires_acknowledgment: bool = False
    display_popup: bool = True
    play_sound: bool = False
    action_required: bool = False
    
    @classmethod
    def from_notification_data(cls, data: Dict[str, Any]) -> 'SecurityAlert':
        """Tạo SecurityAlert từ notification data"""
        try:
            return cls(
                alert_id=data.get('notification_id', str(int(time.time()))),
                agent_id=data.get('agent_id', ''),
                alert_type=data.get('type', 'security_rule_violation'),
                severity=data.get('severity', 'Medium'),
                risk_score=data.get('risk_score', 50),
                title=data.get('title', '🚨 Security Alert'),
                description=data.get('description', 'Security threat detected'),
                rule_name=data.get('rule_name', 'Security Rule'),
                rule_description=data.get('rule_description', 'Security rule triggered'),
                threat_description=data.get('threat_description', 'Potential security threat'),
                event_details=data.get('event_details', {}),
                timestamp=datetime.now(),
                requires_acknowledgment=data.get('requires_acknowledgment', False),
                display_popup=data.get('display_popup', True),
                play_sound=data.get('play_sound', False),
                action_required=data.get('action_required', False)
            )
        except Exception as e:
            logging.getLogger(__name__).error(f"Error creating SecurityAlert: {e}")
            # Return minimal alert on error
            return cls(
                alert_id=str(int(time.time())),
                agent_id=data.get('agent_id', ''),
                alert_type='security_event',
                severity='Medium',
                risk_score=50,
                title='🚨 Security Alert',
                description='Security event detected',
                rule_name='Security Rule',
                rule_description='Security rule triggered',
                threat_description='Security threat detected',
                event_details={},
                timestamp=datetime.now()
            )

# Định nghĩa file agent_id dùng chung
AGENT_ID_FILE = Path(__file__).parent.parent.parent / '.agent_id'

class ServerCommunication:
    """Enhanced Server Communication với Alert Processing"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Server configuration
        server_config = self.config.get('server', {})
        self.server_host = server_config.get('host', '192.168.20.85')
        self.server_port = server_config.get('port', 5000)
        self.base_url = f"http://{self.server_host}:{self.server_port}"
        self.auth_token = server_config.get('auth_token', 'edr_agent_auth_2024')
        self.timeout = server_config.get('timeout', 10)
        self.retry_attempts = server_config.get('max_retries', 3)
        
        # Communication state
        self.session = None
        self.is_connected = False
        self.offline_mode = False
        self.consecutive_failures = 0
        self.max_consecutive_failures = 5
        
        # ✅ ENHANCED: Alert handling
        self.agent_id = None
        self.alert_handlers = []  # List of alert handlers
        self.alert_polling_task = None
        self.alert_polling_interval = 30  # Check for alerts every 30 seconds
        self.last_alert_check = 0
        self.processed_alerts = set()  # Track processed alerts to avoid duplicates
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'alerts_received': 0,
            'alerts_processed': 0
        }
        
        # Offline event storage
        self.offline_events = []
        
        self.has_retried_registration = False  # Thêm biến cờ để tránh lặp đăng ký lại
        
        self.logger.info(f"📡 Enhanced Server Communication initialized")
        self.logger.info(f"   🎯 Server URL: {self.base_url}")
        self.logger.info(f"   🚨 Alert polling interval: {self.alert_polling_interval}s")
    
    async def initialize(self):
        """Initialize communication with alert polling"""
        try:
            import aiohttp
            
            # Create session
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.auth_token,
                'User-Agent': 'Linux-EDR-Agent/2.1.0-Enhanced'
            }
            
            self.session = aiohttp.ClientSession(timeout=timeout, headers=headers)
            
            self.logger.info("✅ Enhanced Server communication initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Communication initialization failed: {e}")
            self.offline_mode = True
    
    async def start_alert_polling(self):
        """✅ ENHANCED: Start polling for alerts from server"""
        try:
            if not self.agent_id:
                self.logger.warning("⚠️ No agent_id set - cannot start alert polling")
                return
            
            self.alert_polling_task = asyncio.create_task(
                self._alert_polling_loop(),
                name="alert-polling"
            )
            
            self.logger.info("🚨 Alert polling started")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start alert polling: {e}")
    
    async def stop_alert_polling(self):
        """Stop alert polling"""
        try:
            if self.alert_polling_task and not self.alert_polling_task.done():
                self.alert_polling_task.cancel()
                try:
                    await self.alert_polling_task
                except asyncio.CancelledError:
                    pass
            
            self.logger.info("🛑 Alert polling stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping alert polling: {e}")
    
    async def _alert_polling_loop(self):
        """✅ ENHANCED: Main alert polling loop"""
        self.logger.info("🔄 Alert polling loop started")
        
        try:
            while True:
                try:
                    if self.is_online() and self.agent_id:
                        # Check for new alerts
                        alerts = await self._fetch_alerts()
                        
                        if alerts:
                            self.logger.info(f"📥 Received {len(alerts)} alerts from server")
                            self.stats['alerts_received'] += len(alerts)
                            
                            # Process each alert
                            for alert_data in alerts:
                                await self._process_alert(alert_data)
                    
                    await asyncio.sleep(self.alert_polling_interval)
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"❌ Alert polling error: {e}")
                    await asyncio.sleep(self.alert_polling_interval)
                    
        except Exception as e:
            self.logger.error(f"❌ Alert polling loop failed: {e}")
        finally:
            self.logger.info("🛑 Alert polling loop ended")
    
    async def _fetch_alerts(self) -> List[Dict[str, Any]]:
        """✅ ENHANCED: Fetch alerts from server"""
        try:
            if not self.agent_id:
                return []
            
            url = f"{self.base_url}/api/v1/agents/{self.agent_id}/notifications"
            
            self.logger.debug(f"🔍 Fetching alerts from: {url}")
            
            response = await self._make_request('GET', url)
            
            if response and response.get('success'):
                notifications = response.get('notifications', [])
                
                if notifications:
                    self.logger.info(f"📨 Fetched {len(notifications)} notifications")
                    return notifications
            
            return []
            
        except Exception as e:
            self.logger.error(f"❌ Error fetching alerts: {e}")
            return []
    
    async def _process_alert(self, alert_data: Dict[str, Any]):
        """✅ ENHANCED: Process individual alert"""
        try:
            alert_id = alert_data.get('notification_id', str(int(time.time())))
            
            # Check if already processed
            if alert_id in self.processed_alerts:
                self.logger.debug(f"⏭️ Alert {alert_id} already processed")
                return
            
            # Create SecurityAlert object
            security_alert = SecurityAlert.from_notification_data(alert_data)
            
            self.logger.warning(f"🚨 PROCESSING SECURITY ALERT:")
            self.logger.warning(f"   🆔 Alert ID: {security_alert.alert_id}")
            self.logger.warning(f"   📋 Type: {security_alert.alert_type}")
            self.logger.warning(f"   ⚠️ Severity: {security_alert.severity}")
            self.logger.warning(f"   📊 Risk Score: {security_alert.risk_score}")
            self.logger.warning(f"   📝 Rule: {security_alert.rule_name}")
            
            # Send to all registered alert handlers
            for handler in self.alert_handlers:
                try:
                    if hasattr(handler, 'handle_security_alert') and asyncio.iscoroutinefunction(handler.handle_security_alert):
                        await handler.handle_security_alert(security_alert)
                    elif asyncio.iscoroutinefunction(handler):
                        await handler(security_alert)
                    else:
                        handler(security_alert)
                except Exception as e:
                    self.logger.error(f"❌ Alert handler error: {e}")
            
            # Mark as processed
            self.processed_alerts.add(alert_id)
            self.stats['alerts_processed'] += 1
            
            # Clean old processed alerts (keep last 1000)
            if len(self.processed_alerts) > 1000:
                self.processed_alerts = set(list(self.processed_alerts)[-500:])
            
        except Exception as e:
            self.logger.error(f"❌ Error processing alert: {e}")
    
    def add_alert_handler(self, handler):
        """✅ ENHANCED: Add alert handler"""
        try:
            if handler not in self.alert_handlers:
                self.alert_handlers.append(handler)
                self.logger.info(f"✅ Alert handler added: {type(handler).__name__}")
            
        except Exception as e:
            self.logger.error(f"❌ Error adding alert handler: {e}")
    
    def remove_alert_handler(self, handler):
        """Remove alert handler"""
        try:
            if handler in self.alert_handlers:
                self.alert_handlers.remove(handler)
                self.logger.info(f"🗑️ Alert handler removed: {type(handler).__name__}")
            
        except Exception as e:
            self.logger.error(f"❌ Error removing alert handler: {e}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for alert polling"""
        self.agent_id = agent_id
        self.logger.info(f"🆔 Agent ID set: {agent_id[:12]}...")
    
    async def test_server_connection(self) -> bool:
        """Test server connection with enhanced error handling"""
        try:
            endpoints = [
                "/api/v1/health/check",
                "/api/v1/health",
                "/health",
                "/api/health",
                "/"
            ]
            
            self.logger.info(f"🔍 Testing connection to {self.base_url}")
            
            for endpoint in endpoints:
                try:
                    url = f"{self.base_url}{endpoint}"
                    self.logger.debug(f"🔍 Trying endpoint: {url}")
                    
                    if not self.session:
                        self.logger.error("❌ No HTTP session available for test_server_connection")
                        return False
                    async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status in [200, 404]:
                            self.is_connected = True
                            self.consecutive_failures = 0
                            self.logger.info(f"✅ Server connection test successful (endpoint: {endpoint})")
                            return True
                        else:
                            self.logger.debug(f"⚠️ Endpoint {endpoint} returned status {response.status}")
                            
                except asyncio.TimeoutError:
                    self.logger.debug(f"⚠️ Endpoint {endpoint} timeout")
                    continue
                    
                except aiohttp.ClientConnectorError as e:
                    self.logger.debug(f"⚠️ Endpoint {endpoint} connection error: {e}")
                    continue
                    
                except Exception as e:
                    self.logger.debug(f"⚠️ Endpoint {endpoint} error: {e}")
                    continue
            
            # All endpoints failed
            self.is_connected = False
            self.consecutive_failures += 1
            self.logger.error(f"❌ Connection test failed")
            self.offline_mode = True
            return False
                    
        except Exception as e:
            self.logger.error(f"❌ Connection test failed: {e}")
            self.is_connected = False
            self.consecutive_failures += 1
            self.offline_mode = True
            return False
    
    def is_online(self) -> bool:
        """Check if communication is online"""
        return self.is_connected and not self.offline_mode
    
    async def register_agent(self, registration_data: AgentRegistrationData) -> Dict[str, Any]:
        """Register agent with server"""
        try:
            if self.offline_mode:
                return {'success': False, 'error': 'Offline mode'}
            
            url = f"{self.base_url}/api/v1/agents/register"
            payload = registration_data.to_dict()
            
            response = await self._make_request('POST', url, payload)
            
            if response and response.get('success'):
                agent_id = response.get('agent_id')
                if agent_id:
                    self.set_agent_id(agent_id)
                    # Lưu agent_id mới vào file
                    try:
                        AGENT_ID_FILE.write_text(str(agent_id))
                        self.logger.info(f"✅ Đã lưu agent_id mới vào file (register_agent)")
                    except Exception as e:
                        self.logger.error(f"❌ Không thể lưu agent_id mới (register_agent): {e}")
                    await self.start_alert_polling()
                return response
            else:
                error_msg = response.get('error', 'Unknown error') if response else 'No response'
                self.logger.error(f"❌ Agent registration failed: {error_msg}")
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            self.logger.error(f"❌ Agent registration failed: {e}")
            return {'success': False, 'error': str(e)}
    
    async def send_heartbeat(self, heartbeat_data: AgentHeartbeatData) -> bool:
        """Send heartbeat to server"""
        try:
            if self.offline_mode:
                return False
            
            url = f"{self.base_url}/api/v1/agents/heartbeat"
            payload = heartbeat_data.to_dict()
            
            response = await self._make_request('POST', url, payload)
            
            return response is not None and response.get('success', False)
            
        except Exception as e:
            self.logger.error(f"❌ Heartbeat failed: {e}")
            return False
    
    async def check_health(self) -> bool:
        """Check server health before sending event"""
        try:
            url = f"{self.base_url}/api/v1/health/check"
            if not self.session:
                self.logger.error("❌ No HTTP session available for check_health")
                return False
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    return True
                return False
        except Exception as e:
            self.logger.warning(f"Health check failed: {e}")
            return False

    async def submit_event(self, event_data: EventData) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Submit single event, chỉ gửi khi health check thành công, tự động retry khi offline và tự động đăng ký lại nếu agent not found"""
        retry_interval = 5
        max_retry = None  # Không giới hạn số lần thử lại
        retry_count = 0
        was_offline = self.offline_mode
        while True:
            try:
                if self.offline_mode:
                    self.logger.warning("⚠ Offline mode, thử reconnect...")
                    # Thử reconnect bằng cách test kết nối server
                    try:
                        await self.test_server_connection()
                        if not self.offline_mode:
                            self.logger.info("✅ Đã reconnect thành công!")
                            # Sau khi reconnect, gửi lại toàn bộ event offline
                            if self.offline_events:
                                self.logger.info(f"📤 Đang gửi lại {len(self.offline_events)} event offline sau khi reconnect...")
                                offline_events_copy = self.offline_events.copy()
                                self.offline_events.clear()
                                for offline_event in offline_events_copy:
                                    await self.submit_event(offline_event)
                        else:
                            await asyncio.sleep(retry_interval)
                            continue
                    except Exception:
                        await asyncio.sleep(retry_interval)
                        continue
                # Thêm health check trước khi gửi event
                health_ok = await self.check_health()
                if not health_ok:
                    self.logger.warning("⚠ Health check failed, retrying in 5s...")
                    await asyncio.sleep(retry_interval)
                    continue
                url = f"{self.base_url}/api/v1/events/submit"
                event_dict = event_data.to_dict()
                if 'error' in event_dict:
                    return False, None, f"Event validation error: {event_dict['error']}"
                response = await self._make_request('POST', url, event_dict)
                # --- PATCH: Tự động đăng ký lại nếu agent not found ---
                if response and not response.get('success') and response.get('error'):
                    error_msg = response.get('error', '')
                    if 'Agent' in error_msg and 'not found' in error_msg:
                        if self.has_retried_registration:
                            self.logger.error("❌ Đã thử đăng ký lại agent nhưng vẫn không thành công. Dừng agent.")
                            import sys
                            sys.exit("Agent registration failed. Please check backend or contact admin.")
                        self.has_retried_registration = True
                        self.logger.warning("⚠ Agent not found trên backend, thực hiện đăng ký lại...")
                        # Xóa file agent_id cũ nếu có
                        try:
                            if AGENT_ID_FILE.exists():
                                AGENT_ID_FILE.unlink()
                                self.logger.info("🗑️ Đã xóa file agent_id cũ")
                        except Exception as e:
                            self.logger.error(f"❌ Không thể xóa file agent_id: {e}")
                        # Lấy hostname và ip_address
                        hostname = platform.node() or "linux-edr-agent"
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            s.connect(("8.8.8.8", 80))
                            ip_address = s.getsockname()[0]
                            s.close()
                        except:
                            ip_address = "127.0.0.1"
                        registration_data = create_linux_registration_data(hostname, ip_address)
                        reg_result = await self.register_agent(registration_data)
                        if reg_result.get('success'):
                            # Lưu agent_id mới vào file
                            try:
                                if self.agent_id:
                                    AGENT_ID_FILE.write_text(str(self.agent_id))
                                    self.logger.info("✅ Đã lưu agent_id mới vào file")
                                else:
                                    self.logger.warning("⚠ Không có agent_id mới để lưu vào file")
                            except Exception as e:
                                self.logger.error(f"❌ Không thể lưu agent_id mới: {e}")
                            self.logger.info("✅ Đăng ký lại agent thành công, cần khởi động lại agent để đồng bộ agent_id mới.")
                            import sys
                            sys.exit("Agent ID changed. Please restart the agent to synchronize the new agent_id.")
                        else:
                            self.logger.error(f"❌ Đăng ký lại agent thất bại: {reg_result.get('error')}")
                            import sys
                            sys.exit("Agent registration failed. Please check backend or contact admin.")
                        continue  # Thử lại vòng lặp
                # --- END PATCH ---
                if response and response.get('success'):
                    return True, response, None
                else:
                    error_msg = response.get('error', 'Unknown error') if response else 'No response'
                    self.logger.warning(f"⚠ Gửi event thất bại: {error_msg}, thử lại sau {retry_interval}s")
                    await asyncio.sleep(retry_interval)
                    retry_count += 1
                    if max_retry and retry_count >= max_retry:
                        return False, response, error_msg
            except Exception as e:
                self.logger.warning(f"⚠ Lỗi gửi event: {e}, thử lại sau {retry_interval}s")
                await asyncio.sleep(retry_interval)
                retry_count += 1
                if max_retry and retry_count >= max_retry:
                    return False, None, str(e)
    
    async def submit_event_batch(self, events: List[EventData]) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Submit event batch with fallback to individual submission"""
        try:
            if self.offline_mode:
                self.offline_events.extend(events)
                return False, None, "Offline mode"
            
            if not events:
                return True, {'message': 'No events to submit'}, None
            
            # Try individual submission for Linux agent
            return await self._submit_events_individually(events)
                
        except Exception as e:
            self.logger.debug(f"Batch submission error: {e}")
            return await self._submit_events_individually(events)
    
    async def _submit_events_individually(self, events: List[EventData]) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Submit events individually"""
        try:
            successful_submissions = 0
            failed_submissions = 0
            total_events = len(events)
            
            for event in events:
                success, response, error = await self.submit_event(event)
                if success:
                    successful_submissions += 1
                else:
                    failed_submissions += 1
                    self.logger.debug(f"Individual event submission failed: {error}")
            
            overall_success = successful_submissions > 0
            result_message = f"Individual submission: {successful_submissions}/{total_events} successful"
            
            return overall_success, {'message': result_message, 'successful': successful_submissions, 'failed': failed_submissions}, None
            
        except Exception as e:
            return False, None, f"Individual submission error: {str(e)}"
    
    async def _make_request(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with comprehensive error handling"""
        if not self.session or self.offline_mode:
            return None
        
        try:
            self.stats['total_requests'] += 1
            
            if method.upper() == 'GET':
                async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    result = await self._handle_response(response)
                    if result:
                        self.stats['successful_requests'] += 1
                    else:
                        self.stats['failed_requests'] += 1
                    return result
            elif method.upper() == 'POST':
                async with self.session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    result = await self._handle_response(response)
                    if result:
                        self.stats['successful_requests'] += 1
                    else:
                        self.stats['failed_requests'] += 1
                    return result
            else:
                self.logger.error(f"❌ Unsupported HTTP method: {method}")
                self.stats['failed_requests'] += 1
                return None
                    
        except asyncio.TimeoutError:
            self.logger.warning(f"⚠️ Request timeout for {url}")
            self.consecutive_failures += 1
            self.stats['failed_requests'] += 1
            return None
        except aiohttp.ClientConnectorError as e:
            self.logger.warning(f"⚠️ Connection error for {url}: {e}")
            self.consecutive_failures += 1
            self.offline_mode = True
            self.stats['failed_requests'] += 1
            return None
        except Exception as e:
            self.logger.warning(f"⚠️ Request error for {url}: {e}")
            self.consecutive_failures += 1
            self.stats['failed_requests'] += 1
            return None
    
    async def _handle_response(self, response) -> Optional[Dict]:
        """Handle HTTP response properly"""
        try:
            if response.status == 200:
                try:
                    json_data = await response.json()
                    self.consecutive_failures = 0  # Reset on success
                    return json_data
                except Exception:
                    text = await response.text()
                    return {'success': True, 'message': text}
            else:
                try:
                    error_data = await response.json()
                    return error_data
                except:
                    text = await response.text()
                    return {'error': f'HTTP {response.status}: {text}'}
                    
        except Exception as e:
            return None
    
    async def close(self):
        """Close communication and stop alert polling"""
        try:
            # Stop alert polling
            await self.stop_alert_polling()
            
            # Close session
            if self.session:
                await self.session.close()
                
            self.logger.info("✅ Enhanced Server communication closed")
            
        except Exception as e:
            self.logger.error(f"❌ Error closing communication: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get communication statistics"""
        return {
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'alerts_received': self.stats['alerts_received'],
            'alerts_processed': self.stats['alerts_processed'],
            'is_connected': self.is_connected,
            'offline_mode': self.offline_mode,
            'consecutive_failures': self.consecutive_failures,
            'alert_handlers_count': len(self.alert_handlers),
            'processed_alerts_count': len(self.processed_alerts),
            'alert_polling_interval': self.alert_polling_interval,
            'agent_id': self.agent_id[:12] + '...' if self.agent_id else None
        }

    async def get_pending_alerts(self, agent_id: Optional[str] = None) -> Optional[Dict]:
        """Get pending alert notifications from server (giống agent Windows)"""
        try:
            if self.offline_mode:
                return None
            if agent_id is None:
                agent_id = self.agent_id
            url = f"{self.base_url}/api/v1/agents/{agent_id}/pending-alerts"
            response = await self._make_request('GET', url)
            return response
        except Exception as e:
            self.logger.error(f"❌ get_pending_alerts error: {e}")
            return None

    # Optional: tự động gửi các event còn queue khi online lại
    async def send_queued_events(self):
        if not self.offline_events:
            return
        sent = 0
        for event in self.offline_events[:]:
            ok, _, _ = await self.submit_event(event)
            if ok:
                self.offline_events.remove(event)
                sent += 1
        if sent:
            self.logger.info(f"✅ Sent {sent} queued events after reconnect")

    async def check_agent_id_exists(self, agent_id: str) -> bool:
        """Kiểm tra agent_id có tồn tại trên backend không"""
        try:
            url = f"{self.base_url}/api/v1/agents/{agent_id}/status"
            response = await self._make_request('GET', url)
            if response and isinstance(response, dict):
                return bool(response.get('success', False))
            return False
        except Exception:
            return False