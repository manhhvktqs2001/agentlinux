# agent/core/communication.py - ENHANCED with Realtime Log Streaming
"""
Enhanced Communication Manager with Realtime Log Streaming
Gửi logs realtime và song song lên server không theo tuần tự
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

def serialize_datetime(obj):
    """JSON serializer that handles datetime objects"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, 'isoformat'):
        return obj.isoformat()
    else:
        return str(obj)

class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

@dataclass
class LogEntry:
    """Log entry for realtime transmission"""
    timestamp: str
    level: str
    message: str
    thread_name: str
    logger_name: str
    agent_id: str
    hostname: str
    category: str = "general"
    source: str = "agent"

@dataclass
class ConnectionStats:
    """Connection statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    last_request_time: Optional[datetime] = None
    logs_sent: int = 0
    logs_failed: int = 0

class RealtimeLogHandler(logging.Handler):
    """Custom log handler for realtime log streaming"""
    
    def __init__(self, communication_manager):
        super().__init__()
        self.communication = communication_manager
        self.log_queue = asyncio.Queue(maxsize=1000)
        self.is_running = False
        
    def emit(self, record):
        """Emit log record for realtime transmission"""
        try:
            if self.communication and self.communication.enable_realtime_logs:
                log_entry = LogEntry(
                    timestamp=datetime.fromtimestamp(record.created).isoformat(),
                    level=record.levelname,
                    message=self.format(record),
                    thread_name=record.thread,
                    logger_name=record.name,
                    agent_id=self.communication.agent_id or "unknown",
                    hostname=self.communication.hostname or "unknown",
                    category=self._categorize_log(record),
                    source="agent"
                )
                
                # Add to queue without blocking
                try:
                    self.log_queue.put_nowait(log_entry)
                except asyncio.QueueFull:
                    # Drop oldest log if queue is full
                    try:
                        self.log_queue.get_nowait()
                        self.log_queue.put_nowait(log_entry)
                    except:
                        pass
                        
        except Exception:
            # Don't let logging errors crash the application
            pass
    
    def _categorize_log(self, record):
        """Categorize log based on logger name and message"""
        logger_name = record.name.lower()
        message = record.getMessage().lower()
        
        if 'security' in logger_name or 'security' in message:
            return 'security'
        elif 'network' in logger_name or 'network' in message:
            return 'network'
        elif 'process' in logger_name or 'process' in message:
            return 'process'
        elif 'file' in logger_name or 'file' in message:
            return 'file'
        elif 'authentication' in logger_name or 'auth' in message:
            return 'authentication'
        elif 'system' in logger_name or 'system' in message:
            return 'system'
        elif 'error' in message or record.levelno >= logging.ERROR:
            return 'error'
        elif 'warning' in message or record.levelno >= logging.WARNING:
            return 'warning'
        else:
            return 'general'

class ServerCommunication:
    """Enhanced Server Communication with Realtime Log Streaming"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.config = config_manager.get_config()
        self.logger = logging.getLogger(__name__)
        
        # Server configuration
        server_config = self.config.get('server', {})
        self.server_host = server_config.get('host', 'localhost')
        self.server_port = server_config.get('port', 5000)
        self.base_url = f"http://{self.server_host}:{self.server_port}"
        self.auth_token = server_config.get('auth_token', 'edr_agent_auth_2024')
        self.timeout = server_config.get('timeout', 30)
        self.retry_attempts = server_config.get('max_retries', 3)
        
        # Event submission configuration
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
        
        # 🚀 NEW: Realtime log streaming features
        self.agent_id = None
        self.hostname = None
        self.log_queue = asyncio.Queue(maxsize=2000)  # Increased buffer for logs
        self.log_sending_tasks = []  # Multiple parallel log sending tasks
        self.log_sending_interval = 2  # Send logs every 2 seconds (faster)
        self.enable_realtime_logs = self.config.get('agent', {}).get('enable_realtime_logs', True)
        self.log_batch_size = self.config.get('agent', {}).get('log_batch_size', 15)
        self.max_parallel_log_senders = 3  # Maximum parallel log sender tasks
        
        # 🚀 NEW: Thread-specific log tracking
        self.thread_logs = {}  # Store logs by thread name
        self.thread_queues = {}  # Separate queue for each thread
        
        # 🚀 NEW: Log categories and priorities
        self.log_categories = {
            'security': {'priority': 1, 'urgent': True},
            'error': {'priority': 2, 'urgent': True},
            'authentication': {'priority': 3, 'urgent': True},
            'network': {'priority': 4, 'urgent': False},
            'process': {'priority': 5, 'urgent': False},
            'file': {'priority': 6, 'urgent': False},
            'system': {'priority': 7, 'urgent': False},
            'warning': {'priority': 8, 'urgent': False},
            'general': {'priority': 9, 'urgent': False}
        }
        
        # 🚀 NEW: Realtime log handler
        self.realtime_handler = None
        
        self.logger.info(f"📡 Enhanced Server Communication initialized")
        self.logger.info(f"   🎯 Server URL: {self.base_url}")
        self.logger.info(f"   🔑 Auth Token: {self.auth_token}")
        if self.enable_realtime_logs:
            self.logger.info(f"   📝 Realtime logs enabled - batch size: {self.log_batch_size}")
            self.logger.info(f"   🔄 Parallel log senders: {self.max_parallel_log_senders}")
        else:
            self.logger.info(f"   📝 Realtime logs disabled")
    
    async def initialize(self):
        """Initialize with realtime log streaming"""
        try:
            import aiohttp
            
            timeout = aiohttp.ClientTimeout(total=30)
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.auth_token,
                'User-Agent': 'Linux-EDR-Agent/2.1.0'
            }
            
            self.session = aiohttp.ClientSession(timeout=timeout, headers=headers)
            
            # Test connection
            await self._test_connection()
            
            # 🚀 NEW: Initialize realtime log streaming
            if self.enable_realtime_logs:
                await self._initialize_realtime_logging()
            
            self.logger.info("✅ Enhanced Server communication initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Communication initialization failed: {e}")
            self.offline_mode = True
    
    async def _initialize_realtime_logging(self):
        """Initialize realtime log streaming system"""
        try:
            self.logger.info("🚀 Initializing realtime log streaming...")
            
            # Create and configure realtime log handler
            self.realtime_handler = RealtimeLogHandler(self)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            self.realtime_handler.setFormatter(formatter)
            
            # Add handler to root logger to capture all logs
            root_logger = logging.getLogger()
            root_logger.addHandler(self.realtime_handler)
            
            # Set appropriate log level for realtime streaming
            self.realtime_handler.setLevel(logging.INFO)
            
            # 🚀 Start multiple parallel log sending tasks
            for i in range(self.max_parallel_log_senders):
                task = asyncio.create_task(
                    self._realtime_log_sender(f"log-sender-{i}"),
                    name=f"realtime-log-sender-{i}"
                )
                self.log_sending_tasks.append(task)
            
            # 🚀 Start thread-specific log processing
            asyncio.create_task(self._thread_log_processor())
            
            # 🚀 Start urgent log processor for high-priority logs
            asyncio.create_task(self._urgent_log_processor())
            
            self.logger.info(f"✅ Realtime log streaming initialized with {self.max_parallel_log_senders} parallel senders")
            
        except Exception as e:
            self.logger.error(f"❌ Realtime log streaming initialization failed: {e}")
    
    async def _realtime_log_sender(self, sender_id: str):
        """Parallel realtime log sender task"""
        sender_logger = logging.getLogger(f"log_sender.{sender_id}")
        
        try:
            while True:
                try:
                    # Collect logs for sending
                    logs_to_send = []
                    
                    # Wait for at least one log
                    try:
                        log_entry = await asyncio.wait_for(
                            self.realtime_handler.log_queue.get() if self.realtime_handler else asyncio.sleep(1),
                            timeout=self.log_sending_interval
                        )
                        if log_entry:
                            logs_to_send.append(log_entry)
                    except asyncio.TimeoutError:
                        # No logs available, continue
                        continue
                    
                    # Collect additional logs up to batch size
                    while len(logs_to_send) < self.log_batch_size:
                        try:
                            log_entry = self.realtime_handler.log_queue.get_nowait() if self.realtime_handler else None
                            if log_entry:
                                logs_to_send.append(log_entry)
                            else:
                                break
                        except asyncio.QueueEmpty:
                            break
                    
                    if logs_to_send:
                        # Send logs to server
                        success = await self._send_logs_batch(logs_to_send, sender_id)
                        
                        if success:
                            self.stats.logs_sent += len(logs_to_send)
                            sender_logger.debug(f"📤 {sender_id} sent {len(logs_to_send)} logs")
                        else:
                            self.stats.logs_failed += len(logs_to_send)
                            sender_logger.warning(f"❌ {sender_id} failed to send {len(logs_to_send)} logs")
                    
                except Exception as e:
                    sender_logger.error(f"❌ {sender_id} error: {e}")
                    await asyncio.sleep(1)
                    
        except asyncio.CancelledError:
            sender_logger.info(f"🛑 {sender_id} stopped")
        except Exception as e:
            sender_logger.error(f"❌ {sender_id} failed: {e}")
    
    async def _thread_log_processor(self):
        """Process logs by thread for parallel sending"""
        try:
            while True:
                try:
                    # Process thread-specific queues
                    for thread_name, queue in list(self.thread_queues.items()):
                        if not queue.empty():
                            # Send thread logs immediately
                            asyncio.create_task(self._send_thread_logs(thread_name))
                    
                    await asyncio.sleep(0.5)  # Check every 500ms
                    
                except Exception as e:
                    self.logger.error(f"❌ Thread log processor error: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"❌ Thread log processor failed: {e}")
    
    async def _urgent_log_processor(self):
        """Process urgent logs immediately"""
        try:
            while True:
                try:
                    if self.realtime_handler and not self.realtime_handler.log_queue.empty():
                        # Check for urgent logs
                        urgent_logs = []
                        temp_logs = []
                        
                        # Process available logs
                        while not self.realtime_handler.log_queue.empty() and len(urgent_logs) < 5:
                            try:
                                log_entry = self.realtime_handler.log_queue.get_nowait()
                                category_info = self.log_categories.get(log_entry.category, {})
                                
                                if category_info.get('urgent', False):
                                    urgent_logs.append(log_entry)
                                else:
                                    temp_logs.append(log_entry)
                                    
                            except asyncio.QueueEmpty:
                                break
                        
                        # Put non-urgent logs back
                        for log in temp_logs:
                            try:
                                self.realtime_handler.log_queue.put_nowait(log)
                            except asyncio.QueueFull:
                                break
                        
                        # Send urgent logs immediately
                        if urgent_logs:
                            asyncio.create_task(self._send_urgent_logs(urgent_logs))
                    
                    await asyncio.sleep(0.1)  # Check every 100ms for urgent logs
                    
                except Exception as e:
                    self.logger.error(f"❌ Urgent log processor error: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"❌ Urgent log processor failed: {e}")
    
    async def _send_thread_logs(self, thread_name: str):
        """Send logs from specific thread"""
        try:
            if thread_name not in self.thread_queues:
                return
            
            queue = self.thread_queues[thread_name]
            logs_to_send = []
            
            # Collect logs from thread queue
            while not queue.empty() and len(logs_to_send) < self.log_batch_size:
                try:
                    log_entry = queue.get_nowait()
                    logs_to_send.append(log_entry)
                except:
                    break
            
            if logs_to_send:
                await self._send_logs_batch(logs_to_send, f"thread-{thread_name}")
                
        except Exception as e:
            self.logger.error(f"❌ Thread log sending error for {thread_name}: {e}")
    
    async def _send_urgent_logs(self, urgent_logs: List[LogEntry]):
        """Send urgent logs immediately"""
        try:
            await self._send_logs_batch(urgent_logs, "urgent-sender")
            self.logger.debug(f"🚨 Sent {len(urgent_logs)} urgent logs")
            
        except Exception as e:
            self.logger.error(f"❌ Urgent log sending error: {e}")
    
    async def _send_logs_batch(self, logs: List[LogEntry], sender_id: str) -> bool:
        """Send batch of logs to server"""
        try:
            if self.offline_mode or not logs:
                return False
            
            url = f"{self.base_url}/api/v1/logs/realtime"
            
            # Prepare log data
            log_data = {
                'agent_id': self.agent_id,
                'hostname': self.hostname,
                'sender_id': sender_id,
                'timestamp': datetime.now().isoformat(),
                'log_count': len(logs),
                'logs': [
                    {
                        'timestamp': log.timestamp,
                        'level': log.level,
                        'message': log.message,
                        'thread_name': log.thread_name,
                        'logger_name': log.logger_name,
                        'category': log.category,
                        'source': log.source,
                        'agent_id': log.agent_id,
                        'hostname': log.hostname
                    }
                    for log in logs
                ]
            }
            
            # Send to server
            response = await self._make_request('POST', url, log_data)
            
            if response and response.get('success'):
                return True
            else:
                return False
                
        except Exception as e:
            # Don't log errors in log sending to avoid infinite loops
            return False
    
    def set_agent_info(self, agent_id: str, hostname: str = None):
        """Set agent information for log streaming"""
        self.agent_id = agent_id
        self.hostname = hostname or "unknown"
        
        if self.realtime_handler:
            # Update the handler's communication reference
            self.realtime_handler.communication = self
    
    async def add_log_entry(self, level: str, message: str, category: str = "general", 
                           thread_name: str = None, logger_name: str = None):
        """Manually add log entry for realtime streaming"""
        try:
            if not self.enable_realtime_logs or not self.realtime_handler:
                return
            
            import threading
            
            log_entry = LogEntry(
                timestamp=datetime.now().isoformat(),
                level=level,
                message=message,
                thread_name=thread_name or threading.current_thread().name,
                logger_name=logger_name or "manual",
                agent_id=self.agent_id or "unknown",
                hostname=self.hostname or "unknown",
                category=category,
                source="manual"
            )
            
            # Add to appropriate queue based on urgency
            category_info = self.log_categories.get(category, {})
            if category_info.get('urgent', False):
                # Send urgent logs immediately
                asyncio.create_task(self._send_urgent_logs([log_entry]))
            else:
                # Add to regular queue
                try:
                    self.realtime_handler.log_queue.put_nowait(log_entry)
                except asyncio.QueueFull:
                    # Queue is full, drop oldest
                    try:
                        self.realtime_handler.log_queue.get_nowait()
                        self.realtime_handler.log_queue.put_nowait(log_entry)
                    except:
                        pass
                        
        except Exception as e:
            # Don't let log entry errors crash the application
            pass
    
    async def close(self):
        """Close communication and stop log streaming"""
        try:
            # Stop realtime log streaming
            if self.log_sending_tasks:
                self.logger.info("🛑 Stopping realtime log streaming...")
                for task in self.log_sending_tasks:
                    if not task.done():
                        task.cancel()
                
                # Wait for tasks to complete
                await asyncio.gather(*self.log_sending_tasks, return_exceptions=True)
                self.log_sending_tasks.clear()
            
            # Remove realtime handler
            if self.realtime_handler:
                root_logger = logging.getLogger()
                root_logger.removeHandler(self.realtime_handler)
                self.realtime_handler = None
            
            # Close session
            if self.session:
                await self.session.close()
                
            self.logger.info("✅ Enhanced Server communication closed")
            
        except Exception as e:
            self.logger.error(f"❌ Error closing communication: {e}")
    
    # ... (keep all existing methods from original communication.py)
    
    async def _test_connection(self):
        """Test connection with proper error handling and retry logic"""
        try:
            url = f"{self.base_url}/api/v1/health/check"
            self.logger.info(f"🔍 Testing connection to {url}")
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    async with self.session.get(url, timeout=10) as response:
                        if response.status == 200:
                            self.is_connected = True
                            self.consecutive_failures = 0
                            self.logger.info("✅ Basic connectivity successful")
                            return True
                        else:
                            self.logger.warning(f"⚠️ Server returned status {response.status} (attempt {attempt + 1}/{max_retries})")
                            
                except asyncio.TimeoutError:
                    self.logger.warning(f"⚠️ Connection timeout (attempt {attempt + 1}/{max_retries})")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)
                        
                except aiohttp.ClientConnectorError as e:
                    self.logger.warning(f"⚠️ Connection error (attempt {attempt + 1}/{max_retries}): {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)
                        
                except Exception as e:
                    self.logger.warning(f"⚠️ Unexpected error (attempt {attempt + 1}/{max_retries}): {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)
            
            # All attempts failed
            self.is_connected = False
            self.consecutive_failures += 1
            self.logger.error(f"❌ Connection test failed after {max_retries} attempts")
            return False
                    
        except Exception as e:
            self.logger.error(f"❌ Connection test failed: {e}")
            self.is_connected = False
            self.consecutive_failures += 1
            return False
    
    async def _make_request(self, method: str, url: str, payload: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request with comprehensive error handling"""
        if not self.session:
            self.logger.error("❌ No active session available")
            return None
        
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
                        return await self._handle_response(response)
                elif method.upper() == 'POST':
                    if payload:
                        try:
                            json_payload = json.dumps(payload, cls=JSONEncoder, default=serialize_datetime)
                        except Exception as e:
                            self.logger.error(f"❌ JSON serialization failed: {e}")
                            return None
                    else:
                        json_payload = None
                    
                    async with self.session.post(url, data=json_payload, headers=headers, timeout=self.timeout) as response:
                        return await self._handle_response(response)
                else:
                    self.logger.error(f"❌ Unsupported HTTP method: {method}")
                    return None
                    
            except asyncio.TimeoutError:
                self.logger.warning(f"⚠️ Request timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    self.logger.error(f"❌ Request failed after {max_retries} attempts due to timeout")
                    
            except aiohttp.ClientConnectorError as e:
                self.logger.warning(f"⚠️ Connection error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    self.logger.error(f"❌ Request failed after {max_retries} attempts due to connection error")
                    
            except aiohttp.ClientError as e:
                self.logger.warning(f"⚠️ Client error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    self.logger.error(f"❌ Request failed after {max_retries} attempts due to client error")
                    
            except Exception as e:
                self.logger.warning(f"⚠️ Unexpected error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    self.logger.error(f"❌ Request failed after {max_retries} attempts due to unexpected error")
        
        return None
    
    async def _handle_response(self, response) -> Optional[Dict]:
        """Handle HTTP response properly"""
        try:
            if response.status == 200:
                try:
                    json_data = await response.json()
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
    
    # ... (include all other existing methods from original communication.py)
    
    def get_realtime_stats(self) -> Dict[str, Any]:
        """Get realtime log streaming statistics"""
        return {
            'enabled': self.enable_realtime_logs,
            'logs_sent': self.stats.logs_sent,
            'logs_failed': self.stats.logs_failed,
            'active_senders': len([t for t in self.log_sending_tasks if not t.done()]),
            'queue_size': self.realtime_handler.log_queue.qsize() if self.realtime_handler else 0,
            'thread_queues': len(self.thread_queues),
            'log_categories': list(self.log_categories.keys()),
            'batch_size': self.log_batch_size,
            'sending_interval': self.log_sending_interval
        }