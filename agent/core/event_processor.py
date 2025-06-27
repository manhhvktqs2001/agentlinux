# agent/core/event_processor.py - FIXED Linux Event Processor
"""
Linux Event Processor - FIXED VERSION  
Process and submit events to EDR server with proper imports
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
from agent.core.communication import ServerCommunication  # FIXED IMPORT
from agent.schemas.events import EventData

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
    Linux Event Processor - FIXED VERSION
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
        
        self.logger.info(f"🔄 Linux Event Processor initialized")
        self.logger.info(f"   📦 Batch Size: {self.batch_size}")
        self.logger.info(f"   📊 Queue Size: {self.max_queue_size}")
        self.logger.info(f"   👥 Workers: {self.num_workers}")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for event processing"""
        self.agent_id = agent_id
        self.logger.info(f"Agent ID set for event processing: {agent_id}")
    
    async def start(self):
        """Start event processor"""
        try:
            self.is_running = True
            
            self.logger.info("🚀 Starting Linux Event Processor...")
            
            # Start worker tasks
            for worker_id in range(self.num_workers):
                task = asyncio.create_task(self._worker_loop(worker_id))
                self.worker_tasks.append(task)
            
            # Start batch processors
            for processor_id in range(self.num_batch_processors):
                task = asyncio.create_task(self._batch_processor_loop(processor_id))
                self.batch_processor_tasks.append(task)
            
            # Start monitoring task
            asyncio.create_task(self._monitoring_loop())
            
            self.logger.info(f"✅ Event Processor started with {self.num_workers} workers")
            
        except Exception as e:
            self.logger.error(f"❌ Event processor start failed: {e}")
            raise
    
    async def stop(self):
        """Stop event processor gracefully"""
        try:
            self.logger.info("🛑 Stopping Linux Event Processor...")
            
            self.is_running = False
            
            # Cancel worker tasks
            for task in self.worker_tasks + self.batch_processor_tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for tasks to complete
            if self.worker_tasks + self.batch_processor_tasks:
                await asyncio.gather(*self.worker_tasks, *self.batch_processor_tasks, 
                                   return_exceptions=True)
            
            # Process remaining events
            await self._flush_queues()
            
            self.logger.info("✅ Event Processor stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping event processor: {e}")
    
    async def add_event(self, event_data: EventData):
        """Add event to processing queue"""
        try:
            # Set agent_id if not present
            if self.agent_id and not event_data.agent_id:
                event_data.agent_id = self.agent_id
            
            if not event_data.agent_id:
                self.logger.error("❌ Event missing agent_id")
                return
            
            # Add to queue
            try:
                self.event_queue.put_nowait(event_data)
                self.stats.events_received += 1
                
            except asyncio.QueueFull:
                self.logger.warning("⚠️ Event queue full - dropping event")
                self.stats.events_failed += 1
            
        except Exception as e:
            self.logger.error(f"❌ Error adding event: {e}")
    
    async def _worker_loop(self, worker_id: int):
        """Worker loop for event processing"""
        self.logger.info(f"👷 Worker {worker_id} started")
        
        batch_buffer = []
        last_batch_time = time.time()
        
        try:
            while self.is_running:
                try:
                    # Get event from queue
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
                        not self.is_running
                    )
                    
                    if should_send_batch and batch_buffer:
                        # Send batch to batch processor
                        await self._send_batch_to_processor(worker_id, batch_buffer.copy())
                        batch_buffer.clear()
                        last_batch_time = current_time
                
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
            if not batch:
                return
            
            batch_item = {
                'worker_id': worker_id,
                'batch': batch,
                'batch_size': len(batch),
                'timestamp': time.time()
            }
            
            await self.batch_queue.put(batch_item)
            
        except Exception as e:
            self.logger.error(f"❌ Error sending batch from worker {worker_id}: {e}")
    
    async def _batch_processor_loop(self, processor_id: int):
        """Batch processor loop"""
        self.logger.info(f"📦 Batch processor {processor_id} started")
        
        try:
            while self.is_running:
                try:
                    # Get batch from queue
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
                
                except Exception as e:
                    self.logger.error(f"❌ Batch processor {processor_id} error: {e}")
                    await asyncio.sleep(1)
                    
        except Exception as e:
            self.logger.error(f"❌ Batch processor {processor_id} failed: {e}")
        finally:
            self.logger.info(f"📦 Batch processor {processor_id} stopped")
    
    async def _process_batch(self, processor_id: int, batch_item: Dict) -> bool:
        """Process event batch"""
        try:
            batch = batch_item['batch']
            if not batch:
                return True
            
            start_time = time.time()
            
            # Submit batch to server
            success, response, error = await self.communication.submit_event_batch(batch)
            
            # Track processing time
            processing_time = time.time() - start_time
            self.processing_times.append(processing_time)
            
            if success:
                self.logger.debug(f"📤 Batch submitted successfully: {len(batch)} events")
                return True
            else:
                self.logger.warning(f"⚠️ Batch submission failed: {error}")
                return False
            
        except Exception as e:
            self.logger.error(f"❌ Batch processing error: {e}")
            return False
    
    async def _monitoring_loop(self):
        """Monitor event processor performance"""
        try:
            while self.is_running:
                try:
                    # Update statistics
                    self._update_stats()
                    
                    # Log statistics every 2 minutes
                    if int(time.time()) % 120 == 0:
                        self._log_stats()
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"❌ Monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self.logger.error(f"❌ Monitoring loop failed: {e}")
    
    def _update_stats(self):
        """Update processing statistics"""
        try:
            # Calculate processing rate
            if self.processing_times:
                avg_time = sum(self.processing_times) / len(self.processing_times)
                self.stats.processing_rate = 1.0 / max(avg_time, 0.001)  # events per second
            
            # Calculate queue utilization
            queue_size = self.event_queue.qsize()
            self.stats.events_queued = queue_size
            self.stats.queue_utilization = queue_size / self.max_queue_size
            
            self.stats.last_processed = datetime.now()
            
        except Exception as e:
            self.logger.debug(f"Error updating stats: {e}")
    
    def _log_stats(self):
        """Log processing statistics"""
        try:
            self.logger.info("📊 Event Processor Statistics:")
            self.logger.info(f"   📥 Events Received: {self.stats.events_received}")
            self.logger.info(f"   📤 Events Sent: {self.stats.events_sent}")
            self.logger.info(f"   ❌ Events Failed: {self.stats.events_failed}")
            self.logger.info(f"   📊 Queue Size: {self.stats.events_queued}/{self.max_queue_size}")
            self.logger.info(f"   ⚡ Processing Rate: {self.stats.processing_rate:.2f} events/sec")
            self.logger.info(f"   📊 Queue Utilization: {self.stats.queue_utilization:.1%}")
            
        except Exception as e:
            self.logger.debug(f"Error logging stats: {e}")
    
    async def _flush_queues(self):
        """Flush remaining events from queues"""
        try:
            self.logger.info("🔄 Flushing event queues...")
            
            events_flushed = 0
            
            # Flush event queue
            while not self.event_queue.empty():
                try:
                    event = self.event_queue.get_nowait()
                    # Try to send immediately
                    success, _, _ = await self.communication.submit_event(event)
                    if success:
                        events_flushed += 1
                except:
                    break
            
            # Flush batch queue
            while not self.batch_queue.empty():
                try:
                    batch_item = self.batch_queue.get_nowait()
                    for event in batch_item['batch']:
                        success, _, _ = await self.communication.submit_event(event)
                        if success:
                            events_flushed += 1
                except:
                    break
            
            self.logger.info(f"🔄 Flushed {events_flushed} events")
            
        except Exception as e:
            self.logger.error(f"❌ Error flushing queues: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            'events_received': self.stats.events_received,
            'events_sent': self.stats.events_sent,
            'events_failed': self.stats.events_failed,
            'events_queued': self.stats.events_queued,
            'processing_rate': self.stats.processing_rate,
            'queue_utilization': self.stats.queue_utilization,
            'last_processed': self.stats.last_processed.isoformat(),
            'batch_size': self.batch_size,
            'max_queue_size': self.max_queue_size,
            'num_workers': self.num_workers,
            'num_batch_processors': self.num_batch_processors,
            'is_running': self.is_running,
            'agent_id': self.agent_id,
            'success_rate': (self.stats.events_sent / max(self.stats.events_received, 1)) * 100
        }

# Backward compatibility aliases
LinuxEventProcessor = EventProcessor
ParallelEventProcessor = EventProcessor