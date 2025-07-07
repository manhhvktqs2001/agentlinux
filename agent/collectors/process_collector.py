# agent/collectors/process_collector.py - OPTIMIZED Process Collector
"""
OPTIMIZED Linux Process Collector
Reduced event spam with intelligent filtering and throttling
"""

import psutil
import os
import time
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict, deque
import asyncio

from agent.collectors.base_collector import LinuxBaseCollector
from agent.schemas.events import EventData

class LinuxProcessCollector(LinuxBaseCollector):
    """✅ OPTIMIZED: Linux Process Collector with spam reduction"""
    
    def __init__(self, config_manager=None):
        """✅ CONTINUOUS REALTIME: Initialize Linux Process Collector"""
        super().__init__(config_manager, "LinuxProcessCollector")
        
        # ✅ CONTINUOUS REALTIME: Very fast polling
        self.polling_interval = 2  # 2 seconds, luôn quét nhanh
        self.max_events_per_batch = self.config.get('collection', {}).get('max_events_per_collection', 5)
        
        # ✅ CONTINUOUS REALTIME: No deduplication for realtime streaming
        self.enable_deduplication = self.config.get('collection', {}).get('enable_deduplication', False)
        self.event_dedup_window = self.config.get('collection', {}).get('deduplication_window', 0)
        
        # Không lọc process sống ngắn
        self.min_process_lifetime = 0
        self.exclude_short_lived = False
        
        # ✅ CONTINUOUS REALTIME: Higher rate limits
        self.max_events_per_minute = self.config.get('filters', {}).get('max_process_events_per_minute', 100)  # 100 events/minute
        
        # Process tracking
        self.monitored_processes = {}
        self.last_scan_pids = set()
        self.events_this_minute = 0
        self.last_minute_reset = time.time()
        self.recent_events = {}
        
        # Statistics
        self.stats = {
            'process_creation_events': 0,
            'process_termination_events': 0,
            'process_running_events': 0,
            'interesting_process_events': 0,
            'total_process_events': 0,
            'filtered_events': 0,
            'rate_limited_events': 0
        }
        
        # Không loại trừ bất kỳ tiến trình nào
        self.excluded_process_names = []
        self.excluded_paths = []
        self.exclude_kernel_threads = False
        self.exclude_agent_activity = False
        
        # Interesting processes for security monitoring
        self.interesting_processes = {
            'system': ['systemd', 'init', 'kthreadd', 'ksoftirqd'],
            'network': ['sshd', 'apache2', 'nginx', 'postgres', 'mysql'],
            'security': ['auditd', 'fail2ban', 'ufw', 'iptables'],
            'monitoring': ['top', 'htop', 'iotop', 'nethogs'],
            'development': ['python', 'node', 'java', 'gcc', 'make'],
            'browsers': ['firefox', 'chrome', 'chromium', 'safari'],
            'terminals': ['bash', 'zsh', 'fish', 'tmux', 'screen']
        }
        
        self.logger.info("✅ Linux LinuxProcessCollector initialized")
        self.logger.info("🐧 Continuous Realtime Linux Process Collector initialized")
        self.logger.info(f"   ⏱ Polling Interval: {self.polling_interval}s")
        self.logger.info(f"   📊 Max Events/Batch: {self.max_events_per_batch}")
        self.logger.info(f"   ⏳ Min Process Lifetime: {self.min_process_lifetime}s")
        self.logger.info(f"   🚫 Excluded Processes: {len(self.excluded_process_names)}")
        self.logger.info(f"   🔄 Continuous Mode: Enabled")
        self.logger.info(f"   📡 Realtime Streaming: No Delays")
    
    async def _collect_data(self):
        """✅ REALTIME: Collect and send process events immediately"""
        try:
            start_time = time.time()
            events = []
            current_pids = set()
            
            # ✅ REALTIME: Rate limiting check
            if not self._check_rate_limit():
                self.logger.debug("Rate limit reached, skipping collection")
                return []
            
            # Get current processes with filtering
            try:
                filtered_processes = 0
                total_processes = 0
                
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                               'username', 'ppid', 'status', 'cpu_percent', 'memory_info']):
                    try:
                        total_processes += 1
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        if not pid or not proc_info.get('name'):
                            filtered_processes += 1
                            continue
                        
                        # ✅ REALTIME: Apply comprehensive filtering
                        if self._should_filter_process(proc_info):
                            filtered_processes += 1
                            continue
                        
                        current_pids.add(pid)
                        
                        # ✅ REALTIME: Check for new process
                        if pid not in self.monitored_processes:
                            # ✅ REALTIME: Additional lifetime check
                            if self._check_process_lifetime(proc_info):
                                event = await self._create_process_start_event(proc_info)
                                if event and self._is_event_worth_sending(event):
                                    # ✅ REALTIME: Send event immediately
                                    await self._send_event_immediately(event)
                                    events.append(event)
                                    self.stats['process_creation_events'] += 1
                                    self._increment_event_count()
                                    
                                    # ✅ REALTIME: Log immediately
                                    agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                                    self.logger.info(f"🐧 Linux Process Event: Start - Agent: {agent_id_short}...")
                        
                        # ✅ REALTIME: ALWAYS create event for running process (continuous monitoring)
                        else:
                            # Create event for existing running process
                            event = await self._create_process_running_event(proc_info)
                            if event and self._is_event_worth_sending(event):
                                # ✅ REALTIME: Send event immediately
                                await self._send_event_immediately(event)
                                events.append(event)
                                self.stats['process_running_events'] += 1
                                self._increment_event_count()
                                
                                # ✅ REALTIME: Log immediately
                                agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                                self.logger.info(f"🐧 Linux Process Event: Running - Agent: {agent_id_short}...")
                        
                        # Update tracking with minimal data
                        self.monitored_processes[pid] = {
                            'name': proc_info.get('name'),
                            'create_time': proc_info.get('create_time'),
                            'last_seen': time.time()
                        }
                        
                        # ✅ REALTIME: Stop if we hit batch limit
                        if len(events) >= self.max_events_per_batch:
                            break
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error processing process {pid}: {e}")
                        continue
            
            except Exception as e:
                self.logger.error(f"Error iterating processes: {e}")
                return []
            
            # ✅ REALTIME: Only process terminations for interesting processes
            if len(events) < self.max_events_per_batch:
                terminated_pids = self.last_scan_pids - current_pids
                for pid in list(terminated_pids)[:2]:  # Limit to 2 termination events
                    if pid in self.monitored_processes:
                        proc_data = self.monitored_processes[pid]
                        if self._is_interesting_process(proc_data.get('name', '')):
                            event = await self._create_process_end_event(pid, proc_data)
                            if event and self._is_event_worth_sending(event):
                                # ✅ REALTIME: Send event immediately
                                await self._send_event_immediately(event)
                                events.append(event)
                                self.stats['process_termination_events'] += 1
                                self._increment_event_count()
                                
                                # ✅ REALTIME: Log immediately
                                agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                                self.logger.info(f"🐧 Linux Process Event: End - Agent: {agent_id_short}...")
                        del self.monitored_processes[pid]
            
            # Update tracking
            self.last_scan_pids = current_pids
            self.stats['total_process_events'] += len(events)
            self.stats['filtered_events'] += filtered_processes
            
            # ✅ REALTIME: Log collection efficiency
            collection_time = (time.time() - start_time) * 1000
            if events:
                self.logger.info(f"🐧 Generated {len(events)} process events ({collection_time:.1f}ms)")
                self.logger.debug(f"   📊 Filtered {filtered_processes}/{total_processes} processes")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Process collection failed: {e}")
            return []
    
    def _should_filter_process(self, proc_info: Dict) -> bool:
        """✅ OPTIMIZATION: Comprehensive process filtering"""
        try:
            name = proc_info.get('name', '').lower()
            exe = proc_info.get('exe', '')
            cmdline = proc_info.get('cmdline', [])
            status = proc_info.get('status', '')
            
            # Filter by name
            if any(excluded in name for excluded in self.excluded_process_names):
                return True
            
            # Filter by executable path
            if exe and any(excluded in exe for excluded in self.excluded_paths):
                return True
            
            # Filter kernel threads
            if self.exclude_kernel_threads and self._is_kernel_thread(proc_info):
                return True
            
            # Filter zombie/dead processes
            if status in ['zombie', 'dead']:
                return True
            
            # Filter processes with no command line (usually kernel threads)
            if not cmdline or len(cmdline) == 0:
                return True
            
            # Filter our own agent processes
            if self.exclude_agent_activity and cmdline:
                cmdline_str = ' '.join(cmdline).lower()
                if any(agent_term in cmdline_str for agent_term in ['edr-agent', 'python3 main.py']):
                    return True
            
            return False
            
        except Exception:
            return True  # Filter on error
    
    def _check_process_lifetime(self, proc_info: Dict) -> bool:
        """✅ OPTIMIZATION: Check if process has lived long enough"""
        try:
            if not self.exclude_short_lived:
                return True
            
            create_time = proc_info.get('create_time', 0)
            if create_time > 0:
                lifetime = time.time() - create_time
                return lifetime >= self.min_process_lifetime
            
            return True  # Allow if we can't determine age
            
        except Exception:
            return True
    
    def _is_kernel_thread(self, proc_info: Dict) -> bool:
        """Check if process is a kernel thread"""
        try:
            name = proc_info.get('name', '')
            exe = proc_info.get('exe')
            cmdline = proc_info.get('cmdline', [])
            
            # Kernel threads have names in brackets
            if name.startswith('[') and name.endswith(']'):
                return True
            
            # Kernel threads don't have executable paths
            if not exe:
                return True
            
            # Kernel threads don't have command lines
            if not cmdline or len(cmdline) == 0:
                return True
            
            # Check common kernel thread patterns
            kernel_patterns = ['kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog', 'kworker']
            return any(pattern in name for pattern in kernel_patterns)
            
        except Exception:
            return False
    
    def _is_interesting_process(self, process_name: str) -> bool:
        """Check if process is interesting for security monitoring"""
        if not process_name:
            return False
        
        process_lower = process_name.lower()
        for category, processes in self.interesting_processes.items():
            if any(proc.lower() in process_lower for proc in processes):
                return True
        return False
    
    def _check_rate_limit(self) -> bool:
        """✅ OPTIMIZATION: Check if we're within rate limits"""
        current_time = time.time()
        
        # Reset counter every minute
        if current_time - self.last_minute_reset >= 60:
            self.events_this_minute = 0
            self.last_minute_reset = current_time
        
        if self.events_this_minute >= self.max_events_per_minute:
            self.stats['rate_limited_events'] += 1
            return False
        
        return True
    
    def _increment_event_count(self):
        """Increment event count for rate limiting"""
        self.events_this_minute += 1
    
    def _is_event_worth_sending(self, event: EventData) -> bool:
        """✅ OPTIMIZATION: Check if event is worth sending (deduplication)"""
        try:
            # Create event key for deduplication
            event_key = f"{event.event_type}_{event.process_name}_{event.event_action}"
            current_time = time.time()
            
            # Check if we've seen this event recently
            if event_key in self.recent_events:
                last_time = self.recent_events[event_key]
                if current_time - last_time < self.event_dedup_window:
                    return False
            
            # Update recent events
            self.recent_events[event_key] = current_time
            
            # Clean old entries
            cutoff_time = current_time - self.event_dedup_window
            self.recent_events = {
                key: timestamp for key, timestamp in self.recent_events.items()
                if timestamp > cutoff_time
            }
            
            return True
            
        except Exception:
            return True  # Send on error
    
    async def _create_process_start_event(self, proc_info: Dict) -> Optional[EventData]:
        """✅ OPTIMIZED: Create process start event with validation"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create process event - missing agent_id")
                return None
            
            # Extract process information
            pid = proc_info.get('pid')
            name = proc_info.get('name', 'Unknown')
            exe = proc_info.get('exe')
            cmdline = proc_info.get('cmdline', [])
            username = proc_info.get('username')
            ppid = proc_info.get('ppid')
            
            # Ensure proper data types
            if pid is not None:
                pid = int(pid)
            if ppid is not None:
                ppid = int(ppid)
            
            # Create command line string safely
            cmdline_str = ""
            if cmdline and isinstance(cmdline, list):
                cmdline_str = ' '.join(str(arg) for arg in cmdline[:5])  # Limit to first 5 args
            elif isinstance(cmdline, str):
                cmdline_str = cmdline[:200]  # Limit length
            
            # Determine severity
            severity = "Info"
            if self._is_interesting_process(name):
                severity = "Medium"
                self.stats['interesting_process_events'] += 1
            
            # Create event
            event = EventData(
                event_type="Process",
                event_action="Start",
                severity=severity,
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                process_id=pid,
                process_name=name,
                process_path=exe,
                command_line=cmdline_str,
                parent_pid=ppid,
                process_user=username,
                
                description=f"Linux Process Started: {name} (PID: {pid})",
                
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'is_interesting': self._is_interesting_process(name),
                    'create_time': proc_info.get('create_time'),
                    'monitoring_method': 'optimized_psutil_scan',
                    'cpu_percent': proc_info.get('cpu_percent', 0),
                    'memory_mb': self._get_memory_mb(proc_info.get('memory_info'))
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid process event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Process start event creation failed: {e}")
            return None
    
    async def _create_process_end_event(self, pid: int, proc_info: Dict) -> Optional[EventData]:
        """✅ OPTIMIZED: Create process end event"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create process end event - missing agent_id")
                return None
            
            name = proc_info.get('name', 'Unknown')
            create_time = proc_info.get('create_time', 0)
            last_seen = proc_info.get('last_seen', time.time())
            
            # Calculate lifetime
            lifetime = last_seen - create_time if create_time > 0 else 0
            
            event = EventData(
                event_type="Process",
                event_action="Stop",
                severity="Info",
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                process_id=int(pid),
                process_name=name,
                
                description=f"Linux Process Ended: {name} (PID: {pid}, ran {lifetime:.1f}s)",
                
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'termination_time': time.time(),
                    'process_lifetime': lifetime,
                    'monitoring_method': 'optimized_process_tracking'
                }
            )
            
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid process end event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Process end event creation failed: {e}")
            return None
    
    async def _create_process_running_event(self, proc_info: Dict) -> Optional[EventData]:
        """✅ REALTIME: Create event for continuously running process"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create process running event - missing agent_id")
                return None
            
            # Extract process information
            pid = proc_info.get('pid')
            name = proc_info.get('name', 'Unknown')
            exe = proc_info.get('exe')
            cmdline = proc_info.get('cmdline', [])
            username = proc_info.get('username')
            ppid = proc_info.get('ppid')
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_info = proc_info.get('memory_info')
            
            # Ensure proper data types
            if pid is not None:
                pid = int(pid)
            if ppid is not None:
                ppid = int(ppid)
            
            # Create command line string safely
            cmdline_str = ""
            if cmdline and isinstance(cmdline, list):
                cmdline_str = ' '.join(str(arg) for arg in cmdline[:5])  # Limit to first 5 args
            elif isinstance(cmdline, str):
                cmdline_str = cmdline[:200]  # Limit length
            
            # Determine severity based on process type
            severity = "Info"
            if self._is_interesting_process(name):
                severity = "Medium"
            
            # Create event for running process
            event = EventData(
                event_type="Process",
                event_action="Running",
                severity=severity,
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                process_id=pid,
                process_name=name,
                process_path=exe,
                command_line=cmdline_str,
                parent_pid=ppid,
                process_user=username,
                
                description=f"Linux Process Running: {name} (PID: {pid})",
                
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'is_interesting': self._is_interesting_process(name),
                    'create_time': proc_info.get('create_time'),
                    'monitoring_method': 'continuous_realtime_scan',
                    'cpu_percent': cpu_percent,
                    'memory_mb': self._get_memory_mb(memory_info),
                    'status': proc_info.get('status', 'running'),
                    'scan_timestamp': time.time()
                }
            )
            
            # Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid process running event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Process running event creation failed: {e}")
            return None
    
    def _get_process_category(self, process_name: str) -> str:
        """Get process category"""
        if not process_name:
            return 'unknown'
        
        process_lower = process_name.lower()
        for category, processes in self.interesting_processes.items():
            if any(proc.lower() in process_lower for proc in processes):
                return category
        return 'other'
    
    def _get_memory_mb(self, memory_info):
        """✅ FIXED: Properly handle psutil memory_info object"""
        try:
            if memory_info and hasattr(memory_info, 'rss'):
                return memory_info.rss / 1024 / 1024  # Convert bytes to MB
            return 0
        except Exception:
            return 0
    
    async def _send_event_immediately(self, event: EventData):
        """✅ REALTIME: Send event immediately to event processor"""
        try:
            self.logger.info(f"🔍 Attempting to send event immediately: {event.process_name}")
            
            if self.event_processor:
                self.logger.info(f"✅ Event processor found, sending event: {event.process_name}")
                # Send event directly to event processor for immediate processing
                await self.event_processor.add_event(event)
                self.logger.info(f"✅ Event sent immediately: {event.process_name}")
            else:
                self.logger.error("❌ No event processor available for immediate sending")
                self.logger.error(f"❌ Event processor is: {self.event_processor}")
        except Exception as e:
            self.logger.error(f"❌ Failed to send event immediately: {e}")
            import traceback
            self.logger.error(f"❌ Traceback: {traceback.format_exc()}")
    
    def get_stats(self) -> Dict:
        """Get detailed process collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Linux_Process_Optimized',
            'process_creation_events': self.stats['process_creation_events'],
            'process_termination_events': self.stats['process_termination_events'],
            'process_running_events': self.stats['process_running_events'],
            'interesting_process_events': self.stats['interesting_process_events'],
            'total_process_events': self.stats['total_process_events'],
            'filtered_events': self.stats['filtered_events'],
            'rate_limited_events': self.stats['rate_limited_events'],
            'monitored_processes_count': len(self.monitored_processes),
            'excluded_process_names_count': len(self.excluded_process_names),
            'excluded_paths_count': len(self.excluded_paths),
            'min_process_lifetime': self.min_process_lifetime,
            'max_events_per_minute': self.max_events_per_minute,
            'events_this_minute': self.events_this_minute,
            'optimization_version': '2.1.0-ContinuousRealtime'
        })
        return base_stats

    async def _collection_loop(self):
        """✅ CONTINUOUS REALTIME: Continuous collection loop with no delays"""
        self.logger.info(f"🔄 Starting Linux collection loop: {self.collector_name}")
        
        try:
            while self.is_running:
                try:
                    # ✅ CONTINUOUS REALTIME: Collect data immediately
                    events = await self._collect_data()
                    
                    # ✅ CONTINUOUS REALTIME: Send events immediately
                    if events:
                        for event in events:
                            await self._send_event_immediately(event)
                            self.logger.info(f"📡 Continuous Event Sent: {event.process_name}")
                    
                    # ✅ CONTINUOUS REALTIME: Very short sleep for continuous monitoring
                    await asyncio.sleep(self.polling_interval)
                    
                except asyncio.CancelledError:
                    self.logger.info(f"🛑 Collection loop cancelled: {self.collector_name}")
                    break
                except Exception as e:
                    self.logger.error(f"❌ Collection loop error: {e}")
                    await asyncio.sleep(5)  # Short delay on error
                    
        except Exception as e:
            self.logger.error(f"❌ Collection loop failed: {e}")
        finally:
            self.logger.info(f"🛑 Collection loop stopped: {self.collector_name}")

    async def start(self):
        """✅ CONTINUOUS REALTIME: Start process collector with continuous monitoring"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info(f"🚀 Starting Linux collector: {self.collector_name}")
            
            # ✅ CONTINUOUS REALTIME: Start our custom collection loop
            asyncio.create_task(self._collection_loop())
            
            self.logger.info(f"✅ Linux collector started: {self.collector_name}")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} start failed: {e}")
            self.is_running = False
            raise Exception(f"Linux collector start failed: {e}")