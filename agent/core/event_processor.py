# agent/core/event_processor.py - FIXED Linux Event Processor
"""
Linux Event Processor - FIXED VERSION WITH PROPER CLEANUP
Process and submit events to EDR server with proper task management
"""

import asyncio
import logging
import time
import threading
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import deque, defaultdict
from dataclasses import dataclass, field

from agent.core.config_manager import ConfigManager
from agent.core.communication import ServerCommunication
from agent.schemas.events import EventData
from agent.utils.security_notifications import LinuxSecurityNotifier

@dataclass
class ProcessingStats:
    """Event processing statistics"""
    events_received: int = 0
    events_sent: int = 0
    events_failed: int = 0
    events_queued: int = 0
    processing_rate: float = 0.0
    queue_utilization: float = 0.0
    last_processed: datetime = field(default_factory=datetime.now)

class EventProcessor:
    """
    Linux Event Processor - FIXED VERSION WITH PROPER CLEANUP
    Handles event processing and submission to server
    """
    
    def __init__(self, config_manager: ConfigManager, communication: ServerCommunication):
        self.config_manager = config_manager
        self.communication = communication
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.agent_config = self.config.get('agent', {})
        
        # Processing configuration
        self.batch_size = self.agent_config.get('event_batch_size', 50)
        self.batch_timeout = 2.0  # 2 seconds
        self.max_queue_size = self.agent_config.get('event_queue_size', 1000)
        
        # Event queue
        self.event_queue = asyncio.Queue(maxsize=self.max_queue_size)
        self.batch_queue = asyncio.Queue(maxsize=100)
        
        # Processing state
        self.is_running = False
        self.agent_id: Optional[str] = None
        self.shutdown_event = asyncio.Event()  # ✅ FIXED: Add shutdown event
        
        # Worker tasks
        self.worker_tasks = []
        self.batch_processor_tasks = []
        self.num_workers = 2
        self.num_batch_processors = 1
        
        # Statistics
        self.stats = ProcessingStats()
        self.processing_times = deque(maxlen=1000)
        
        # Thread safety
        self._lock = threading.Lock()
        
        # ✅ FIXED: Enhanced Security Notification System (like Windows)
        self.security_notifier = LinuxSecurityNotifier(config_manager)
        self.security_notifier.set_communication(communication)
        self.security_notifier.enabled = True
        self.security_notifier.show_server_rules = True
        self.security_notifier.show_local_rules = False
        self.security_notifier.show_risk_based_alerts = True
        
        self.logger.info(f"🔄 Linux Event Processor initialized")
        self.logger.info(f"   📦 Batch Size: {self.batch_size}")
        self.logger.info(f"   📊 Queue Size: {self.max_queue_size}")
        self.logger.info(f"   👥 Workers: {self.num_workers}")
        self.logger.info(f"   🔔 Security Notifier: Enabled")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for event processing"""
        self.agent_id = agent_id
        self.logger.info(f"Agent ID set for event processing: {agent_id}")
    
    async def start(self):
        """✅ FIXED: Start event processor with proper task management"""
        try:
            self.is_running = True
            self.shutdown_event.clear()  # ✅ FIXED: Clear shutdown event
            
            self.logger.info("🚀 Starting Linux Event Processor...")
            
            # Start worker tasks
            for worker_id in range(self.num_workers):
                task = asyncio.create_task(
                    self._worker_loop(worker_id),
                    name=f"worker-{worker_id}"  # ✅ FIXED: Add task names
                )
                self.worker_tasks.append(task)
            
            # Start batch processors
            for processor_id in range(self.num_batch_processors):
                task = asyncio.create_task(
                    self._batch_processor_loop(processor_id),
                    name=f"batch-processor-{processor_id}"  # ✅ FIXED: Add task names
                )
                self.batch_processor_tasks.append(task)
            
            # Start monitoring task
            monitoring_task = asyncio.create_task(
                self._monitoring_loop(),
                name="event-processor-monitor"  # ✅ FIXED: Add task name
            )
            self.worker_tasks.append(monitoring_task)
            
            self.logger.info(f"✅ Event Processor started with {self.num_workers} workers")
            
        except Exception as e:
            self.logger.error(f"❌ Event processor start failed: {e}")
            raise
    
    async def stop(self):
        """✅ FIXED: Stop event processor gracefully with proper cleanup"""
        try:
            self.logger.info("🛑 Stopping Linux Event Processor...")
            
            # Signal shutdown
            self.is_running = False
            self.shutdown_event.set()
            
            # ✅ FIXED: Cancel tasks gracefully
            all_tasks = self.worker_tasks + self.batch_processor_tasks
            if all_tasks:
                self.logger.info(f"🧹 Cancelling {len(all_tasks)} processor tasks...")
                
                # Cancel all tasks
                for task in all_tasks:
                    if not task.done():
                        task.cancel()
                
                # Wait for tasks to complete with timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*all_tasks, return_exceptions=True),
                        timeout=10.0  # 10 second timeout
                    )
                    self.logger.info("✅ All processor tasks stopped successfully")
                except asyncio.TimeoutError:
                    self.logger.warning("⚠️ Some processor tasks took too long to stop")
                except Exception as e:
                    self.logger.warning(f"⚠️ Error stopping processor tasks: {e}")
            
            # Process remaining events
            await self._flush_queues()
            
            # Clear task lists
            self.worker_tasks.clear()
            self.batch_processor_tasks.clear()
            
            self.logger.info("✅ Event Processor stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping event processor: {e}")
    
    async def add_event(self, event_data: EventData):
        """✅ REALTIME: Add event and send immediately"""
        try:
            # ✅ FIXED: Better logging that handles None process_name
            event_identifier = self._get_event_identifier(event_data)
            self.logger.info(f"📥 Event processor received event: {event_identifier}")
            
            # Set agent_id if not present
            if self.agent_id and not event_data.agent_id:
                event_data.agent_id = self.agent_id
            
            if not event_data.agent_id:
                self.logger.error("❌ Event missing agent_id")
                return
            
            # ✅ REALTIME: Send event immediately instead of queuing
            if not self.shutdown_event.is_set():
                try:
                    self.logger.info(f"🚀 Sending event immediately: {event_identifier}")
                    # Send event immediately to server
                    success = await self._send_event_immediately(event_data)
                    
                    if success:
                        self.stats.events_sent += 1
                        self.logger.info(f"✅ Event sent successfully: {event_identifier}")
                    else:
                        self.stats.events_failed += 1
                        self.logger.warning(f"⚠️ Failed to send event: {event_identifier}")
                    
                except Exception as e:
                    self.logger.error(f"❌ Error sending event immediately: {e}")
                    self.stats.events_failed += 1
            else:
                self.logger.warning(f"⚠️ Shutdown in progress, dropping event: {event_identifier}")
            
        except Exception as e:
            self.logger.error(f"❌ Error adding event: {e}")
            import traceback
            self.logger.error(f"❌ Traceback: {traceback.format_exc()}")
    
    def _get_event_identifier(self, event_data: EventData) -> str:
        """✅ NEW: Get meaningful event identifier for logging"""
        try:
            # For process events, use process name
            if event_data.process_name:
                return event_data.process_name
            
            # For file events, use file name
            if event_data.file_name:
                return f"File:{event_data.file_name}"
            
            # For network events, use destination IP
            if event_data.destination_ip:
                return f"Network:{event_data.destination_ip}"
            
            # For authentication events, use login user
            if event_data.login_user:
                return f"Auth:{event_data.login_user}"
            
            # For system events, use description or event action
            if event_data.description:
                # Extract meaningful part from description
                desc = event_data.description
                if ":" in desc:
                    return desc.split(":", 1)[1].strip()[:80]  # First 80 chars after colon
                return desc[:80]  # First 80 chars
            
            # Fallback to event type and action
            return f"{event_data.event_type}:{event_data.event_action}"
            
        except Exception as e:
            self.logger.debug(f"Error getting event identifier: {e}")
            return f"{event_data.event_type}:{event_data.event_action}"
    
    async def _send_event_immediately(self, event_data: EventData) -> bool:
        """✅ REALTIME: Send single event immediately to server and process response"""
        try:
            event_identifier = self._get_event_identifier(event_data)
            self.logger.info(f"🌐 Attempting to send event to server: {event_identifier}")
            if not self.communication:
                self.logger.error("❌ No communication available")
                return False
            self.logger.info(f"📡 Communication found, submitting event: {event_identifier}")
            # Send event immediately
            success, response, error = await self.communication.submit_event(event_data)
            if success:
                self.logger.info(f"✅ Event submitted successfully to server: {event_identifier}")
                
                # ✅ FIXED: Process server response for alerts and actions (like Windows)
                if response:
                    await self._process_server_response(response, event_data)
                
                # Sau khi gửi thành công, thử gửi lại các event offline nếu có
                if self.communication.offline_events:
                    self.logger.info(f"📤 Đang gửi lại {len(self.communication.offline_events)} event offline...")
                    offline_events_copy = self.communication.offline_events.copy()
                    self.communication.offline_events.clear()
                    for offline_event in offline_events_copy:
                        await self._send_event_immediately(offline_event)
                return True
            else:
                self.logger.warning(f"⚠️ Event submission failed: {error}")
                # Nếu gửi thất bại, lưu lại event vào offline_events
                self.communication.offline_events.append(event_data)
                return False
        except Exception as e:
            self.logger.error(f"❌ Error in immediate event sending: {e}")
            import traceback
            self.logger.error(f"❌ Traceback: {traceback.format_exc()}")
            # Nếu lỗi, lưu lại event vào offline_events
            if self.communication:
                self.communication.offline_events.append(event_data)
            return False
    
    async def _process_server_response(self, server_response: Dict[str, Any], original_event: EventData):
        """✅ FIXED: Process server response for alerts and actions (like Windows)"""
        try:
            # In ra toàn bộ response server gửi về cho agent để debug
            self.logger.warning(f"==== RAW SERVER RESPONSE TO AGENT ====")
            self.logger.warning(json.dumps(server_response, indent=2, ensure_ascii=False))
            # Check if response contains alerts or actions
            alerts_generated = server_response.get('alerts_generated', [])
            alerts = server_response.get('alerts', [])
            action = server_response.get('action')
            threat_detected = server_response.get('threat_detected', False)
            rule_triggered = server_response.get('rule_triggered')
            # Process alerts if any
            if alerts_generated or alerts or threat_detected or rule_triggered:
                self.logger.warning("🚨 ========== SERVER RESPONSE CONTAINS ALERTS/ACTIONS ==========")
                self.logger.warning(f"📄 RAW SERVER RESPONSE: {json.dumps(server_response, indent=2)}")
                # Convert response to alert format if needed
                if not alerts_generated and not alerts and (threat_detected or rule_triggered):
                    # Create alert from response data
                    alert_data = {
                        'id': f'response_alert_{int(time.time())}',
                        'alert_id': f'response_alert_{int(time.time())}',
                        'rule_id': server_response.get('rule_id'),
                        'rule_name': server_response.get('rule_name', rule_triggered or 'Unknown Rule'),
                        'rule_description': server_response.get('rule_description', ''),
                        'title': f"Rule Triggered: {rule_triggered or 'Unknown Rule'}",
                        'description': server_response.get('threat_description', 'Rule violation detected'),
                        'severity': server_response.get('severity', 'Medium'),
                        'risk_score': server_response.get('risk_score', 50),
                        'detection_method': server_response.get('detection_method', 'Rule Engine'),
                        'event_id': server_response.get('event_id'),
                        'timestamp': datetime.now().isoformat(),
                        'server_generated': True,
                        'rule_violation': True,
                        'process_name': getattr(original_event, 'process_name', None),
                        'process_path': getattr(original_event, 'process_path', None),
                        'file_path': getattr(original_event, 'file_path', None),
                        'source_ip': getattr(original_event, 'source_ip', None),
                        'destination_ip': getattr(original_event, 'destination_ip', None),
                        'action': action
                    }
                    alerts_generated = [alert_data]
                # Process all alerts
                all_alerts = alerts_generated + alerts
                if all_alerts:
                    self.logger.warning(f"🔔 PROCESSING {len(all_alerts)} ALERTS FROM SERVER")
                    for alert in all_alerts:
                        try:
                            await self._display_alert_and_execute_action(alert, original_event, action)
                        except Exception as e:
                            self.logger.error(f"❌ Error processing alert: {e}")
                self.logger.warning("🚨 ========== ALERTS/ACTIONS PROCESSING COMPLETE ==========")
        except Exception as e:
            self.logger.error(f"❌ Error processing server response: {e}")
            import traceback
            self.logger.error(f"❌ Traceback: {traceback.format_exc()}")
    
    async def _display_alert_and_execute_action(self, alert: Dict[str, Any], original_event: EventData, action_from_response=None):
        """✅ FIXED: Display alert and execute action (like Windows)"""
        try:
            self.logger.warning("⚡ ACTION DATA RECEIVED:")
            self.logger.warning(f"   📋 Alert ID: {alert.get('id', 'Unknown')}")
            self.logger.warning(f"   🏷️ Rule: {alert.get('rule_name', 'Unknown')}")
            self.logger.warning(f"   ⚠️ Severity: {alert.get('severity', 'Medium')}")
            self.logger.warning(f"   📊 Risk Score: {alert.get('risk_score', 50)}")
            # Display alert using LinuxSecurityNotifier
            if self.security_notifier and self.security_notifier.enabled:
                alert_obj = type('Alert', (), {
                    'alert_id': alert.get('id', f'alert_{int(time.time())}'),
                    'title': alert.get('title', 'Security Alert'),
                    'rule_name': alert.get('rule_name', 'Unknown Rule'),
                    'rule_description': alert.get('rule_description', ''),
                    'threat_description': alert.get('description', 'Security violation detected'),
                    'severity': alert.get('severity', 'Medium'),
                    'risk_score': alert.get('risk_score', 50),
                    'timestamp': datetime.now(),
                    'requires_acknowledgment': False,
                    'display_popup': True,
                    'play_sound': True,
                    'action_required': False,
                    'event_details': {
                        'event_type': original_event.event_type,
                        'process_name': getattr(original_event, 'process_name', None),
                        'process_path': getattr(original_event, 'process_path', None),
                        'file_path': getattr(original_event, 'file_path', None),
                        'source_ip': getattr(original_event, 'source_ip', None),
                        'destination_ip': getattr(original_event, 'destination_ip', None),
                        'command_line': getattr(original_event, 'command_line', None)
                    }
                })()
                await self.security_notifier.handle_security_alert(alert_obj)
            # Lấy action từ alert hoặc từ response ngoài
            action = alert.get('action') or action_from_response
            if action:
                self.logger.warning("⚡ EXECUTING ACTION FROM SERVER:")
                self.logger.warning(f"   🔧 Action Type: {action.get('action_type', 'Unknown')}")
                action_type = action.get('action_type')
                if action_type == 'kill_process':
                    await self._execute_kill_process_action(action, original_event)
                elif action_type == 'block_network':
                    await self._execute_block_network_action(action, original_event)
                elif action_type == 'quarantine_file':
                    await self._execute_quarantine_file_action(action, original_event)
                else:
                    self.logger.warning(f"⚠️ Unknown action type: {action_type}")
        except Exception as e:
            self.logger.error(f"❌ Error displaying alert and executing action: {e}")
            import traceback
            self.logger.error(f"❌ Traceback: {traceback.format_exc()}")
    
    async def _execute_kill_process_action(self, action: Dict[str, Any], original_event: EventData):
        """Execute kill process action"""
        try:
            # Lấy PID từ action
            pid = action.get('process_id') or action.get('PID') or action.get('target_pid')
            process_name = action.get('process_name', 'Unknown')
            force_kill = action.get('force_kill', True)
            
            if not pid:
                self.logger.error("❌ No PID provided for kill_process action")
                return
            
            self.logger.warning(f"🎯 KILLING PROCESS ON LINUX:")
            self.logger.warning(f"   🔧 PID: {pid}")
            self.logger.warning(f"   📋 Process Name: {process_name}")
            self.logger.warning(f"   💪 Force Kill: {force_kill}")
            
            # Thực thi lệnh kill
            import subprocess
            sig = '-9' if force_kill else ''
            cmd = ["kill"]
            if sig:
                cmd.append(sig)
            cmd.append(str(pid))
            
            self.logger.warning(f"⚡ Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                success_msg = f"✅ Process {process_name} (PID: {pid}) killed successfully"
                self.logger.warning(success_msg)
                await self._show_action_notification("Process Killed", success_msg)
            else:
                error_msg = f"❌ Failed to kill process {process_name} (PID: {pid}): {result.stderr}"
                self.logger.error(error_msg)
                await self._show_action_notification("Process Kill Failed", error_msg)
                
        except Exception as e:
            error_msg = f"❌ Error executing kill process action: {e}"
            self.logger.error(error_msg)
            await self._show_action_notification("Process Kill Error", error_msg)
    
    async def _execute_block_network_action(self, action: Dict[str, Any], original_event: EventData):
        """Execute block network action"""
        try:
            target_ip = action.get('target_ip')
            if not target_ip:
                self.logger.error("❌ No target IP provided for block_network action")
                return
            
            self.logger.warning(f"🎯 BLOCKING NETWORK ON LINUX:")
            self.logger.warning(f"   🌐 Target IP: {target_ip}")
            
            # Execute iptables command
            import subprocess
            cmd = ["iptables", "-A", "OUTPUT", "-d", target_ip, "-j", "DROP"]
            
            self.logger.warning(f"⚡ Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                success_msg = f"✅ Network traffic to {target_ip} blocked successfully"
                self.logger.warning(success_msg)
                await self._show_action_notification("Network Blocked", success_msg)
            else:
                error_msg = f"❌ Failed to block network to {target_ip}: {result.stderr}"
                self.logger.error(error_msg)
                await self._show_action_notification("Network Block Failed", error_msg)
                
        except Exception as e:
            error_msg = f"❌ Error executing block network action: {e}"
            self.logger.error(error_msg)
            await self._show_action_notification("Network Block Error", error_msg)
    
    async def _execute_quarantine_file_action(self, action: Dict[str, Any], original_event: EventData):
        """Execute quarantine file action"""
        try:
            file_path = action.get('file_path')
            if not file_path:
                self.logger.error("❌ No file path provided for quarantine_file action")
                return
            
            self.logger.warning(f"🎯 QUARANTINING FILE ON LINUX:")
            self.logger.warning(f"   📁 File Path: {file_path}")
            
            # Create quarantine directory
            import subprocess
            import os
            quarantine_dir = "/tmp/edr_quarantine"
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Move file to quarantine
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, filename)
            cmd = ["mv", file_path, quarantine_path]
            
            self.logger.warning(f"⚡ Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                success_msg = f"✅ File {filename} quarantined successfully"
                self.logger.warning(success_msg)
                await self._show_action_notification("File Quarantined", success_msg)
            else:
                error_msg = f"❌ Failed to quarantine file {filename}: {result.stderr}"
                self.logger.error(error_msg)
                await self._show_action_notification("File Quarantine Failed", error_msg)
                
        except Exception as e:
            error_msg = f"❌ Error executing quarantine file action: {e}"
            self.logger.error(error_msg)
            await self._show_action_notification("File Quarantine Error", error_msg)
    
    async def _show_action_notification(self, title: str, message: str):
        """Show notification for action result"""
        try:
            if self.security_notifier and self.security_notifier.enabled:
                # Create simple alert for action result
                alert_obj = type('Alert', (), {
                    'alert_id': f'action_{int(time.time())}',
                    'title': title,
                    'rule_name': 'Action Result',
                    'rule_description': '',
                    'threat_description': message,
                    'severity': 'Info',
                    'risk_score': 0,
                    'timestamp': datetime.now(),
                    'requires_acknowledgment': False,
                    'display_popup': True,
                    'play_sound': False,
                    'action_required': False,
                    'event_details': {}
                })()
                
                await self.security_notifier.handle_security_alert(alert_obj)
        except Exception as e:
            self.logger.error(f"❌ Error showing action notification: {e}")

    async def _worker_loop(self, worker_id: int):
        """✅ FIXED: Worker loop with proper shutdown handling"""
        self.logger.info(f"👷 Worker {worker_id} started")
        
        batch_buffer = []
        last_batch_time = time.time()
        
        try:
            while self.is_running and not self.shutdown_event.is_set():
                try:
                    # Get event from queue with timeout
                    try:
                        event = await asyncio.wait_for(
                            self.event_queue.get(),
                            timeout=0.5
                        )
                        
                        batch_buffer.append(event)
                        
                    except asyncio.TimeoutError:
                        # No event available - check if we should send partial batch
                        pass
                    
                    current_time = time.time()
                    
                    # Check if we should send batch
                    should_send_batch = (
                        len(batch_buffer) >= self.batch_size or
                        (batch_buffer and (current_time - last_batch_time) >= self.batch_timeout) or
                        self.shutdown_event.is_set()  # ✅ FIXED: Send on shutdown
                    )
                    
                    if should_send_batch and batch_buffer:
                        # Send batch to batch processor
                        await self._send_batch_to_processor(worker_id, batch_buffer.copy())
                        batch_buffer.clear()
                        last_batch_time = current_time
                
                except asyncio.CancelledError:
                    self.logger.info(f"👷 Worker {worker_id} cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"❌ Worker {worker_id} error: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"❌ Worker {worker_id} failed: {e}")
        finally:
            # Send remaining events
            if batch_buffer:
                await self._send_batch_to_processor(worker_id, batch_buffer)
            
            self.logger.info(f"👷 Worker {worker_id} stopped")
    
    async def _send_batch_to_processor(self, worker_id: int, batch: List[EventData]):
        """Send batch to batch processor"""
        try:
            if not batch or self.shutdown_event.is_set():
                return
            
            batch_item = {
                'worker_id': worker_id,
                'batch': batch,
                'batch_size': len(batch),
                'timestamp': time.time()
            }
            
            # Try to put in batch queue, but don't wait if shutting down
            try:
                if not self.shutdown_event.is_set():
                    await asyncio.wait_for(
                        self.batch_queue.put(batch_item),
                        timeout=1.0
                    )
            except asyncio.TimeoutError:
                self.logger.warning(f"⚠️ Batch queue timeout for worker {worker_id}")
            
        except Exception as e:
            self.logger.error(f"❌ Error sending batch from worker {worker_id}: {e}")
    
    async def _batch_processor_loop(self, processor_id: int):
        """✅ FIXED: Batch processor loop with proper shutdown handling"""
        self.logger.info(f"📦 Batch processor {processor_id} started")
        
        try:
            while self.is_running and not self.shutdown_event.is_set():
                try:
                    # Get batch from queue with timeout
                    try:
                        batch_item = await asyncio.wait_for(
                            self.batch_queue.get(),
                            timeout=1.0
                        )
                        
                        # Process batch
                        success = await self._process_batch(processor_id, batch_item)
                        
                        if success:
                            self.stats.events_sent += batch_item['batch_size']
                            self.logger.debug(f"📦 Processor {processor_id}: Sent {batch_item['batch_size']} events")
                        else:
                            self.stats.events_failed += batch_item['batch_size']
                            self.logger.warning(f"⚠️ Processor {processor_id}: Batch failed")
                            
                    except asyncio.TimeoutError:
                        continue  # No batch available
                
                except asyncio.CancelledError:
                    self.logger.info(f"📦 Batch processor {processor_id} cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"❌ Batch processor {processor_id} error: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"❌ Batch processor {processor_id} failed: {e}")
        finally:
            self.logger.info(f"📦 Batch processor {processor_id} stopped")
    
    async def _process_batch(self, processor_id: int, batch_item: Dict) -> bool:
        """Process event batch with improved fallback handling"""
        try:
            batch = batch_item['batch']
            if not batch:
                return True
            
            start_time = time.time()
            
            # Process each event in batch
            for event in batch:
                try:
                    # Send individual event
                    success = await self._send_event_immediately(event)
                    if not success:
                        self.logger.warning(f"⚠️ Failed to send event in batch: {self._get_event_identifier(event)}")
                except Exception as e:
                    self.logger.error(f"❌ Error processing event in batch: {e}")
            
            processing_time = (time.time() - start_time) * 1000
            self.processing_times.append(processing_time)
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Batch processing failed: {e}")
            return False
    
    async def _monitoring_loop(self):
        """✅ FIXED: Monitoring loop with proper shutdown handling"""
        self.logger.info("📊 Event processor monitoring started")
        
        try:
            while self.is_running and not self.shutdown_event.is_set():
                try:
                    # Update and log statistics
                    self._update_stats()
                    self._log_stats()
                    
                    # Sleep for monitoring interval
                    await asyncio.sleep(30)  # 30 seconds
                    
                except asyncio.CancelledError:
                    self.logger.info("📊 Monitoring cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"❌ Monitoring error: {e}")
                    await asyncio.sleep(5)
                    
        except Exception as e:
            self.logger.error(f"❌ Monitoring failed: {e}")
        finally:
            self.logger.info("📊 Event processor monitoring stopped")
    
    def _update_stats(self):
        """Update processing statistics"""
        try:
            # Calculate processing rate
            if self.processing_times:
                self.stats.processing_rate = sum(self.processing_times) / len(self.processing_times)
            
            # Calculate queue utilization
            if self.max_queue_size > 0:
                self.stats.queue_utilization = (self.event_queue.qsize() / self.max_queue_size) * 100
            
            self.stats.last_processed = datetime.now()
            
        except Exception as e:
            self.logger.debug(f"Error updating stats: {e}")
    
    def _log_stats(self):
        """Log processing statistics"""
        try:
            self.logger.info(f"📊 Event Processor Stats:")
            self.logger.info(f"   📥 Events Received: {self.stats.events_received}")
            self.logger.info(f"   📤 Events Sent: {self.stats.events_sent}")
            self.logger.info(f"   ❌ Events Failed: {self.stats.events_failed}")
            self.logger.info(f"   📦 Queue Size: {self.event_queue.qsize()}/{self.max_queue_size}")
            self.logger.info(f"   ⚡ Processing Rate: {self.stats.processing_rate:.1f}ms")
            self.logger.info(f"   📊 Queue Utilization: {self.stats.queue_utilization:.1f}%")
            
        except Exception as e:
            self.logger.debug(f"Error logging stats: {e}")
    
    async def _flush_queues(self):
        """Flush remaining events in queues"""
        try:
            # Flush event queue
            remaining_events = []
            while not self.event_queue.empty():
                try:
                    event = self.event_queue.get_nowait()
                    remaining_events.append(event)
                except asyncio.QueueEmpty:
                    break
            
            if remaining_events:
                self.logger.info(f"📤 Flushing {len(remaining_events)} remaining events...")
                for event in remaining_events:
                    try:
                        await self._send_event_immediately(event)
                    except Exception as e:
                        self.logger.error(f"❌ Error flushing event: {e}")
            
            # Flush batch queue
            remaining_batches = []
            while not self.batch_queue.empty():
                try:
                    batch = self.batch_queue.get_nowait()
                    remaining_batches.append(batch)
                except asyncio.QueueEmpty:
                    break
            
            if remaining_batches:
                self.logger.info(f"📦 Flushing {len(remaining_batches)} remaining batches...")
                for batch in remaining_batches:
                    try:
                        await self._process_batch(0, batch)
                    except Exception as e:
                        self.logger.error(f"❌ Error flushing batch: {e}")
            
        except Exception as e:
            self.logger.error(f"❌ Error flushing queues: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detailed event processor statistics"""
        try:
            return {
                'processor_type': 'Linux_Event_Processor',
                'is_running': self.is_running,
                'agent_id': self.agent_id,
                'events_received': self.stats.events_received,
                'events_sent': self.stats.events_sent,
                'events_failed': self.stats.events_failed,
                'events_queued': self.event_queue.qsize(),
                'processing_rate_ms': self.stats.processing_rate,
                'queue_utilization_percent': self.stats.queue_utilization,
                'last_processed': self.stats.last_processed.isoformat() if self.stats.last_processed else None,
                'worker_tasks': len(self.worker_tasks),
                'batch_processor_tasks': len(self.batch_processor_tasks),
                'batch_size': self.batch_size,
                'batch_timeout': self.batch_timeout,
                'max_queue_size': self.max_queue_size,
                'shutdown_event_set': self.shutdown_event.is_set(),
                'security_notifier_enabled': self.security_notifier.enabled if self.security_notifier else False,
                'linux_event_processing': True
            }
        except Exception as e:
            self.logger.error(f"❌ Error getting stats: {e}")
            return {'error': str(e)}

# Backward compatibility aliases
LinuxEventProcessor = EventProcessor
ParallelEventProcessor = EventProcessor