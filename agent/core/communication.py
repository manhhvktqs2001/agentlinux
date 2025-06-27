# agent/core/communication.py - FIXED Linux Communication Module
"""
Linux Communication Manager - FIXED VERSION
Handles communication with EDR server with proper class naming
"""

import aiohttp
import asyncio
import logging
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from collections import deque
from dataclasses import dataclass

from agent.core.config_manager import ConfigManager
from agent.schemas.agent_data import AgentRegistrationData, AgentHeartbeatData
from agent.schemas.events import EventData

@dataclass
class ConnectionStats:
    """Connection statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    last_request_time: Optional[datetime] = None

class ServerCommunication:
    """✅ FIXED: Server Communication with proper error handling"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.server_config = self.config.get('server', {})
        
        # ✅ FIXED: Server settings with defaults
        self.server_host = self.server_config.get('host', '192.168.20.85')
        self.server_port = self.server_config.get('port', 5000)
        self.base_url = f"http://{self.server_host}:{self.server_port}"
        self.auth_token = self.server_config.get('auth_token', 'edr_agent_auth_2024')
        
        # Connection state
        self.session = None
        self.is_connected = False
        self.offline_mode = False
        
        # Performance tracking
        self.stats = ConnectionStats()
        self.response_times = deque(maxlen=100)
        
        # Error handling
        self.consecutive_failures = 0
        self.max_consecutive_failures = 5
        
        # Offline storage
        self.offline_events = deque(maxlen=1000)
        
        # Thread safety
        self._lock = threading.Lock()
        
        self.logger.info(f"🌐 Server Communication initialized: {self.base_url}")
    
    async def initialize(self):
        """✅ FIXED: Initialize with proper error handling"""
        try:
            import aiohttp
            
            timeout = aiohttp.ClientTimeout(total=30)
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.auth_token,
                'User-Agent': 'Linux-EDR-Agent/2.1.0'
            }
            
            self.session = aiohttp.ClientSession(timeout=timeout, headers=headers)
            
            # ✅ FIXED: Test connection with better error handling
            await self._test_connection()
            
            self.logger.info("✅ Server communication initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Communication initialization failed: {e}")
            self.offline_mode = True
    
    async def _test_connection(self):
        """✅ FIXED: Test connection with proper error handling"""
        try:
            url = f"{self.base_url}/api/v1/health/check"
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    self.is_connected = True
                    self.consecutive_failures = 0
                    self.logger.info("✅ Server connection test successful")
                else:
                    self.logger.warning(f"⚠️ Server returned status {response.status}")
                    
        except Exception as e:
            self.logger.warning(f"⚠️ Server connection test failed: {e}")
            self.is_connected = False
    
    async def register_agent(self, registration_data) -> Optional[Dict]:
        """✅ FIXED: Register agent with complete validation"""
        try:
            if self.offline_mode:
                self.logger.warning("⚠️ Offline mode - cannot register agent")
                return None
            
            url = f"{self.base_url}/api/v1/agents/register"
            
            # ✅ FIXED: Get complete payload with validation
            payload = registration_data.to_dict()
            
            # ✅ FIXED: Validate required fields
            required_fields = ['hostname', 'ip_address', 'operating_system', 'agent_version']
            for field in required_fields:
                if not payload.get(field):
                    raise ValueError(f"Missing required field: {field}")
            
            self.logger.info(f"📡 Registering agent: {payload.get('hostname')}")
            self.logger.info(f"   🌐 IP: {payload.get('ip_address')}")
            self.logger.info(f"   🐧 OS: {payload.get('operating_system')}")
            self.logger.info(f"   🌐 Domain: {payload.get('domain')}")
            
            # ✅ FIXED: Send request with error handling
            response = await self._make_request('POST', url, payload)
            
            if response and (response.get('success') or response.get('agent_id')):
                self.logger.info("✅ Agent registered successfully")
                return response
            else:
                error_msg = response.get('error', 'Unknown error') if response else 'No response'
                self.logger.error(f"❌ Registration failed: {error_msg}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Agent registration error: {e}")
            return None
    
    async def send_heartbeat(self, heartbeat_data: AgentHeartbeatData) -> Optional[Dict]:
        """Send heartbeat to server"""
        try:
            if self.offline_mode:
                return {
                    'success': True,
                    'message': 'Offline mode heartbeat'
                }
            
            url = f"{self.base_url}/api/v1/agents/heartbeat"
            payload = heartbeat_data.to_dict()
            
            response = await self._make_request('POST', url, payload)
            return response
            
        except Exception as e:
            self.logger.debug(f"Heartbeat error: {e}")
            return {
                'success': True,
                'message': 'Heartbeat error',
                'error': str(e)
            }
    
    async def submit_event(self, event_data: EventData) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Submit single event to server"""
        try:
            if self.offline_mode:
                self.offline_events.append(event_data)
                return False, None, "Offline mode - event queued"
            
            if not event_data.agent_id:
                return False, None, "Event missing agent_id"
            
            url = f"{self.base_url}/api/v1/events/submit"
            payload = event_data.to_dict()
            
            response = await self._make_request('POST', url, payload)
            
            if response and response.get('success'):
                return True, response, None
            else:
                error_msg = response.get('error', 'Unknown error') if response else 'No response'
                return False, response, error_msg
                
        except Exception as e:
            self.logger.error(f"❌ Error submitting event: {e}")
            return False, None, str(e)
    
    async def submit_event_batch(self, events: List[EventData]) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Submit batch of events to server"""
        try:
            if self.offline_mode:
                self.offline_events.extend(events)
                return False, None, "Offline mode - events queued"
            
            # Validate all events have agent_id
            invalid_events = [e for e in events if not e.agent_id]
            if invalid_events:
                return False, None, f"Events missing agent_id: {len(invalid_events)}"
            
            url = f"{self.base_url}/api/v1/events/batch-submit"
            payload = {
                'events': [event.to_dict() for event in events],
                'batch_size': len(events),
                'timestamp': datetime.now().isoformat()
            }
            
            response = await self._make_request('POST', url, payload)
            
            if response and response.get('success'):
                return True, response, None
            else:
                error_msg = response.get('error', 'Unknown error') if response else 'No response'
                return False, response, error_msg
                
        except Exception as e:
            self.logger.error(f"❌ Error submitting event batch: {e}")
            return False, None, str(e)
    
    async def _make_request(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """✅ FIXED: Make HTTP request with comprehensive error handling"""
        if not self.session:
            return None
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    async with self.session.get(url) as response:
                        return await self._handle_response(response)
                elif method.upper() == 'POST':
                    async with self.session.post(url, json=payload) as response:
                        return await self._handle_response(response)
                        
            except Exception as e:
                self.logger.debug(f"Request attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
        
        return None
    
    async def _handle_response(self, response) -> Optional[Dict]:
        """✅ FIXED: Handle HTTP response properly"""
        try:
            if response.status == 200:
                try:
                    return await response.json()
                except:
                    text = await response.text()
                    return {'success': True, 'message': text}
            
            elif response.status == 422:
                # ✅ FIXED: Handle validation errors specifically
                try:
                    error_data = await response.json()
                    self.logger.error(f"❌ Validation error (422): {error_data}")
                    return error_data
                except:
                    text = await response.text()
                    self.logger.error(f"❌ Validation error (422): {text}")
                    return {'error': f'Validation error: {text}'}
            
            else:
                text = await response.text()
                self.logger.error(f"❌ HTTP error {response.status}: {text}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Response handling error: {e}")
            return None
    
    async def close(self):
        """Close communication session"""
        try:
            if self.session:
                await self.session.close()
                self.logger.info("✅ Server communication closed")
        except Exception as e:
            self.logger.error(f"❌ Error closing communication: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get communication statistics"""
        return {
            'total_requests': self.stats.total_requests,
            'successful_requests': self.stats.successful_requests,
            'failed_requests': self.stats.failed_requests,
            'success_rate': (self.stats.successful_requests / max(self.stats.total_requests, 1)) * 100,
            'avg_response_time_ms': self.stats.avg_response_time * 1000,
            'last_request_time': self.stats.last_request_time.isoformat() if self.stats.last_request_time else None,
            'is_connected': self.is_connected,
            'offline_mode': self.offline_mode,
            'consecutive_failures': self.consecutive_failures,
            'offline_events_queued': len(self.offline_events),
            'server_url': self.base_url
        }
    
    def is_online(self) -> bool:
        """Check if communication is online"""
        return not self.offline_mode and self.is_connected

# Backward compatibility - also provide the enhanced version
class EnhancedParallelCommunication(ServerCommunication):
    """Enhanced version extends the base ServerCommunication"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__(config_manager)
        self.logger.info("🚀 Enhanced Parallel Communication mode enabled")