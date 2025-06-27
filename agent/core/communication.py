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
from agent.schemas.events import EventData, validate_event_for_database

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
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Server configuration - fix to match current config format
        server_config = self.config.get('server', {})
        self.server_host = server_config.get('host', 'localhost')
        self.server_port = server_config.get('port', 5000)
        self.base_url = f"http://{self.server_host}:{self.server_port}"
        self.auth_token = server_config.get('auth_token', 'edr_agent_auth_2024')
        self.timeout = server_config.get('timeout', 30)
        self.retry_attempts = server_config.get('max_retries', 3)
        
        # 🚀 OPTIMIZATION: Individual vs batch threshold
        self.individual_threshold = self.config.get('agent', {}).get('individual_threshold', 10)
        self.disable_batch_submission = self.config.get('agent', {}).get('disable_batch_submission', False)
        
        # Communication state
        self.session = None
        self.is_connected = False
        self.offline_mode = False
        self.consecutive_failures = 0
        self.max_consecutive_failures = 5
        
        # Statistics
        self.stats = ConnectionStats()
        
        # Offline event storage
        self.offline_events = []
        
        self.logger.info(f"📡 Server Communication initialized")
        self.logger.info(f"   🎯 Server URL: {self.base_url}")
        self.logger.info(f"   🔑 Auth Token: {self.auth_token}")
        self.logger.info(f"   ⏱️ Timeout: {self.timeout}s")
        self.logger.info(f"   🔄 Retry attempts: {self.retry_attempts}")
        self.logger.info(f"   📤 Individual threshold: {self.individual_threshold} events")
        if self.disable_batch_submission:
            self.logger.info(f"   🚫 Batch submission disabled - using individual only")
    
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
        """✅ FIXED: Register agent with complete validation and duplicate handling"""
        try:
            if self.offline_mode:
                self.logger.warning("⚠️ Offline mode - cannot register agent")
                return None
            
            url = f"{self.base_url}/api/v1/agents/register"
            
            # ✅ FIXED: Handle both dict and object inputs
            if hasattr(registration_data, 'to_dict'):
                payload = registration_data.to_dict()
            elif isinstance(registration_data, dict):
                payload = registration_data
            else:
                self.logger.error(f"❌ Invalid registration_data type: {type(registration_data)}")
                return None
            
            # ✅ FIXED: Validate required fields
            required_fields = ['hostname', 'ip_address', 'operating_system', 'agent_version']
            missing_fields = []
            for field in required_fields:
                if not payload.get(field):
                    missing_fields.append(field)
            
            if missing_fields:
                error_msg = f"Missing required fields: {missing_fields}"
                self.logger.error(f"❌ Registration validation failed: {error_msg}")
                return None
            
            # ✅ FIXED: Log registration data
            self.logger.info(f"📝 Registering agent: {payload.get('hostname')} ({payload.get('ip_address')})")
            self.logger.debug(f"📋 Registration payload: {payload}")
            
            # ✅ FIXED: Send request with error handling
            response = await self._make_request('POST', url, payload)
            
            if response and (response.get('success') or response.get('agent_id')):
                agent_id = response.get('agent_id')
                if agent_id:
                    self.agent_id = agent_id
                    self.logger.info(f"✅ Agent registered successfully: {agent_id}")
                return response
            elif response and response.get('error') and 'already registered' in response.get('error', '').lower():
                # ✅ FIXED: Handle already registered case
                self.logger.info("✅ Agent already registered with server")
                return {
                    'success': True,
                    'message': 'Agent already registered',
                    'agent_id': payload.get('agent_id')  # Use existing agent_id
                }
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
        """Submit single event to server with enhanced validation"""
        try:
            if self.offline_mode:
                self.offline_events.append(event_data)
                return False, None, "Offline mode - event queued"
            
            if not event_data.agent_id:
                return False, None, "Event missing agent_id"
            
            # Enhanced validation before submission
            try:
                event_dict = event_data.to_dict()
                if 'error' in event_dict:
                    return False, None, f"Event validation failed: {event_dict['error']}"
                
                # Validate required fields
                required_fields = ['agent_id', 'event_type', 'event_action', 'event_timestamp']
                for field in required_fields:
                    if field not in event_dict or event_dict[field] is None:
                        return False, None, f"Missing required field: {field}"
                
                # Validate event_type values
                valid_event_types = ['Process', 'File', 'Network', 'Authentication', 'System', 'Registry']
                if event_dict.get('event_type') not in valid_event_types:
                    return False, None, f"Invalid event_type: {event_dict.get('event_type')}"
                
                # Validate severity values
                valid_severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
                if event_dict.get('severity') not in valid_severities:
                    return False, None, f"Invalid severity: {event_dict.get('severity')}"
                
                # ✅ FIXED: Log event data for debugging
                self.logger.debug(f"📤 Submitting event: {event_dict.get('event_type')} - {event_dict.get('event_action')}")
                self.logger.debug(f"📋 Event data: {event_dict}")
                
                self.logger.debug(f"✅ Event validation passed: {event_dict.get('event_type')} - {event_dict.get('event_action')}")
                
            except Exception as validation_error:
                self.logger.error(f"❌ Event validation error: {validation_error}")
                return False, None, f"Event validation error: {validation_error}"
            
            url = f"{self.base_url}/api/v1/events/submit"
            payload = event_dict
            
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
        """Submit batch of events to server with automatic fallback to individual submission"""
        try:
            if self.offline_mode:
                self.offline_events.extend(events)
                return False, None, "Offline mode - events queued"
            
            if not events:
                return False, None, "No events to submit"
            
            # ✅ FIXED: Enhanced batch validation
            valid_events = []
            invalid_events = []
            
            for event in events:
                try:
                    event_dict = event.to_dict()
                    if 'error' in event_dict:
                        invalid_events.append(f"Event validation failed: {event_dict['error']}")
                        continue
                    
                    # Basic validation
                    if not event_dict.get('agent_id'):
                        invalid_events.append("Event missing agent_id")
                        continue
                    
                    valid_events.append(event)
                    
                except Exception as e:
                    invalid_events.append(f"Event processing error: {e}")
            
            if invalid_events:
                self.logger.warning(f"⚠️ Found {len(invalid_events)} invalid events: {invalid_events[:3]}...")
            
            if not valid_events:
                return False, None, "No valid events to submit"
            
            # ✅ FIXED: Check if batch submission is disabled
            if self.disable_batch_submission:
                self.logger.info(f"📤 Using individual submission (batch disabled): {len(valid_events)} events")
                return await self._submit_events_individually(valid_events)
            
            # ✅ FIXED: For small batches, use individual submission directly
            if len(valid_events) <= self.individual_threshold:
                self.logger.info(f"📤 Using individual submission for {len(valid_events)} events (≤{self.individual_threshold} threshold)")
                return await self._submit_events_individually(valid_events)
            
            # ✅ FIXED: Try batch submission first, then fallback to individual
            self.logger.info(f"📦 Attempting batch submission for {len(valid_events)} events")
            
            url = f"{self.base_url}/api/v1/events/batch"
            payload = {
                'events': [event.to_dict() for event in valid_events],
                'batch_size': len(valid_events),
                'agent_id': valid_events[0].agent_id if valid_events else None
            }
            
            response = await self._make_request('POST', url, payload)
            
            if response and response.get('success'):
                self.logger.info(f"✅ Batch submission successful: {len(valid_events)} events")
                return True, response, None
            else:
                error_msg = response.get('error', 'Unknown error') if response else 'No response'
                self.logger.warning(f"⚠️ Batch submission failed: {error_msg}")
                
                # ✅ FIXED: Automatic fallback to individual submission
                self.logger.info("🔄 Falling back to individual event submissions...")
                return await self._submit_events_individually(valid_events)
                
        except Exception as e:
            self.logger.error(f"❌ Error submitting batch: {e}")
            # ✅ FIXED: Fallback to individual submission on exception
            if valid_events:
                self.logger.info("🔄 Falling back to individual submissions due to exception...")
                return await self._submit_events_individually(valid_events)
            return False, None, str(e)
    
    async def _submit_events_individually(self, events: List[EventData]) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """Submit events individually with improved rate limiting"""
        try:
            self.logger.info(f"📤 Submitting {len(events)} events individually...")
            
            successful = 0
            failed = 0
            errors = []
            
            # ✅ FIXED: Better rate limiting to prevent overwhelming server
            batch_size = 5  # Submit in smaller batches
            delay_between_batches = 0.2  # 200ms delay between batches
            
            for i, event in enumerate(events):
                try:
                    success, response, error = await self.submit_event(event)
                    if success:
                        successful += 1
                    else:
                        failed += 1
                        errors.append(f"Event {i}: {error}")
                    
                    # ✅ FIXED: Rate limiting - delay every 5 events
                    if (i + 1) % batch_size == 0 and i < len(events) - 1:
                        self.logger.debug(f"⏳ Rate limiting: waiting {delay_between_batches}s after {i + 1} events")
                        await asyncio.sleep(delay_between_batches)
                        
                except Exception as e:
                    failed += 1
                    errors.append(f"Event {i} exception: {e}")
            
            if successful > 0:
                self.logger.info(f"✅ Individual submission successful: {successful}/{len(events)} events")
                if failed > 0:
                    self.logger.warning(f"⚠️ {failed} events failed: {errors[:3]}...")
                return True, {"message": f"Individual: {successful} events submitted"}, None
            else:
                self.logger.error(f"❌ All {len(events)} individual submissions failed")
                return False, None, f"All individual submissions failed: {errors[:3]}"
                
        except Exception as e:
            self.logger.error(f"❌ Individual submission error: {e}")
            return False, None, str(e)
    
    async def _make_request(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """✅ FIXED: Make HTTP request with comprehensive error handling and detailed logging"""
        if not self.session:
            self.logger.error("❌ No session available for request")
            return None
        
        # Prepare headers with authentication
        headers = {
            'Content-Type': 'application/json',
            'X-Agent-Token': self.auth_token
        }
        
        max_retries = self.retry_attempts
        for attempt in range(max_retries):
            try:
                self.logger.debug(f"📡 Making {method} request to {url} (attempt {attempt + 1}/{max_retries})")
                
                if method.upper() == 'GET':
                    async with self.session.get(url, headers=headers, timeout=self.timeout) as response:
                        self.logger.debug(f"📡 GET response status: {response.status}")
                        return await self._handle_response(response)
                elif method.upper() == 'POST':
                    async with self.session.post(url, json=payload, headers=headers, timeout=self.timeout) as response:
                        self.logger.debug(f"📡 POST response status: {response.status}")
                        return await self._handle_response(response)
                        
            except Exception as e:
                self.logger.error(f"❌ Request attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    self.logger.debug(f"⏳ Retrying in 2 seconds...")
                    await asyncio.sleep(2)
        
        self.logger.error(f"❌ All {max_retries} request attempts failed")
        return None
    
    async def _handle_response(self, response) -> Optional[Dict]:
        """✅ FIXED: Handle HTTP response properly with detailed logging"""
        try:
            self.logger.debug(f"📡 Processing response: status={response.status}")
            
            if response.status == 200:
                try:
                    json_data = await response.json()
                    self.logger.debug(f"✅ Success response: {json_data}")
                    return json_data
                except Exception as json_error:
                    text = await response.text()
                    self.logger.debug(f"✅ Success response (text): {text}")
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
            
            elif response.status == 404:
                text = await response.text()
                self.logger.error(f"❌ Endpoint not found (404): {text}")
                return {'error': f'Endpoint not found: {text}'}
            
            elif response.status == 500:
                text = await response.text()
                self.logger.error(f"❌ Server error (500): {text}")
                return {'error': f'Server error: {text}'}
            
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
            'server_url': self.base_url,
            'individual_threshold': self.individual_threshold,
            'submission_strategy': 'individual' if self.individual_threshold > 0 else 'batch'
        }
    
    def is_online(self) -> bool:
        """Check if communication is online"""
        return not self.offline_mode and self.is_connected

    async def test_basic_connectivity(self) -> bool:
        """Test basic server connectivity"""
        try:
            self.logger.info("🔍 Testing basic server connectivity...")
            
            # Test if server is reachable - use a simple endpoint
            test_url = f"{self.base_url}/api/v1/agents/list"
            response = await self._make_request('GET', test_url)
            
            if response:
                self.logger.info("✅ Basic connectivity successful")
                return True
            else:
                self.logger.error("❌ Basic connectivity failed")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Basic connectivity test failed: {e}")
            return False

    async def test_server_connection(self) -> bool:
        """Test server connection and endpoint availability"""
        try:
            self.logger.info("🔍 Testing server connection...")
            
            # Test basic connectivity first
            if not await self.test_basic_connectivity():
                return False
            
            # Test events endpoint
            test_url = f"{self.base_url}/api/v1/events/list"
            response = await self._make_request('GET', test_url)
            
            if response:
                self.logger.info("✅ Server connection successful")
                return True
            else:
                self.logger.error("❌ Server connection failed")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Server connection test failed: {e}")
            return False
    
    async def test_batch_endpoint(self) -> bool:
        """Test batch endpoint specifically"""
        try:
            self.logger.info("🔍 Testing batch endpoint...")
            
            # Create a minimal test event
            from agent.schemas.events import EventData
            test_event = EventData(
                event_type="System",
                event_action="Test",
                agent_id=self.agent_id if hasattr(self, 'agent_id') else "test-agent",
                description="Test event for endpoint validation"
            )
            
            # Test single event submission first
            success, response, error = await self.submit_event(test_event)
            
            if success:
                self.logger.info("✅ Single event submission works")
                
                # Test batch endpoint with single event
                test_batch = {
                    'agent_id': test_event.agent_id,
                    'events': [test_event.to_dict()]
                }
                
                url = f"{self.base_url}/api/v1/events/batch"
                batch_response = await self._make_request('POST', url, test_batch)
                
                if batch_response and 'error' not in batch_response:
                    self.logger.info("✅ Batch endpoint works")
                    return True
                else:
                    self.logger.error(f"❌ Batch endpoint failed: {batch_response}")
                    return False
            else:
                self.logger.error(f"❌ Single event submission failed: {error}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Batch endpoint test failed: {e}")
            return False

    async def test_event_submission(self) -> bool:
        """Test event submission with a simple test event"""
        try:
            from ..schemas.events import EventData, EventType, EventAction, Severity
            
            # Create a simple test event with all required fields
            test_event = EventData(
                agent_id=self.agent_id or "test-agent",
                event_type=EventType.System,
                event_action=EventAction.Created,
                event_timestamp=datetime.now(),
                severity=Severity.Info,
                process_id=1,
                process_name="test_process",
                process_path="/usr/bin/test",
                command_line="test command",
                process_user="testuser",
                raw_event_data={
                    'test': True,
                    'message': 'Test event for validation',
                    'source': 'agent_test'
                }
            )
            
            self.logger.info("🧪 Testing event submission with simple test event...")
            
            success, response, error = await self.submit_event(test_event)
            
            if success:
                self.logger.info("✅ Test event submission successful")
                return True
            else:
                self.logger.error(f"❌ Test event submission failed: {error}")
                if response:
                    self.logger.error(f"📋 Server response: {response}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Test event submission error: {e}")
            return False

# Backward compatibility - also provide the enhanced version
class EnhancedParallelCommunication(ServerCommunication):
    """Enhanced version extends the base ServerCommunication"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__(config_manager)
        self.logger.info("🚀 Enhanced Parallel Communication mode enabled")