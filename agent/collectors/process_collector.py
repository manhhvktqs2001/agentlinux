# agent/collectors/process_collector.py - ENHANCED Task Manager Style Process Collector
"""
ENHANCED Linux Process Collector - Task Manager Style
Continuously monitors all running processes with real-time updates
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

class EnhancedLinuxProcessCollector(LinuxBaseCollector):
    """✅ ENHANCED: Linux Process Collector with Task Manager Style Monitoring"""
    
    def __init__(self, config_manager=None):
        """✅ TASK MANAGER STYLE: Initialize Enhanced Linux Process Collector"""
        super().__init__(config_manager, "EnhancedLinuxProcessCollector")
        
        # ✅ TASK MANAGER STYLE: Very fast real-time polling
        self.polling_interval = 0.5  # 0.5 seconds for real-time updates
        self.max_events_per_batch = 50  # Higher batch size for task manager
        
        # ✅ TASK MANAGER STYLE: No filtering - monitor everything
        self.enable_deduplication = False
        self.event_dedup_window = 0
        
        # ✅ TASK MANAGER STYLE: Monitor all processes regardless of lifetime
        self.min_process_lifetime = 0
        self.exclude_short_lived = False
        
        # ✅ TASK MANAGER STYLE: High rate limits for continuous monitoring
        self.max_events_per_minute = 1000  # 1000 events/minute for task manager
        
        # ✅ TASK MANAGER STYLE: Enhanced process tracking
        self.monitored_processes = {}  # pid -> process_info
        self.last_scan_pids = set()
        self.events_this_minute = 0
        self.last_minute_reset = time.time()
        self.recent_events = {}
        
        # ✅ TASK MANAGER STYLE: Process categories for better organization
        self.process_categories = {
            'system': ['systemd', 'init', 'kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog'],
            'kernel': ['kworker', 'kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog'],
            'network': ['sshd', 'apache2', 'nginx', 'postgres', 'mysql', 'redis', 'mongodb'],
            'security': ['auditd', 'fail2ban', 'ufw', 'iptables', 'firewalld'],
            'monitoring': ['top', 'htop', 'iotop', 'nethogs', 'iftop', 'iotop'],
            'development': ['python', 'node', 'java', 'gcc', 'make', 'git', 'docker'],
            'browsers': ['firefox', 'chrome', 'chromium', 'safari', 'opera'],
            'terminals': ['bash', 'zsh', 'fish', 'tmux', 'screen', 'konsole', 'gnome-terminal'],
            'desktop': ['xfce4', 'gnome', 'kde', 'mate', 'cinnamon', 'lxde'],
            'services': ['systemd', 'dbus', 'NetworkManager', 'pulseaudio', 'cups'],
            'user_apps': ['firefox', 'chrome', 'libreoffice', 'gimp', 'vlc', 'spotify']
        }
        
        # ✅ TASK MANAGER STYLE: Enhanced statistics
        self.stats = {
            'process_creation_events': 0,
            'process_termination_events': 0,
            'process_running_events': 0,
            'process_update_events': 0,
            'interesting_process_events': 0,
            'total_process_events': 0,
            'filtered_events': 0,
            'rate_limited_events': 0,
            'high_cpu_processes': 0,
            'high_memory_processes': 0,
            'suspicious_processes': 0
        }
        
        # ✅ TASK MANAGER STYLE: No exclusions - monitor everything
        self.excluded_process_names = []
        self.excluded_paths = []
        self.exclude_kernel_threads = False
        self.exclude_agent_activity = False
        
        # ✅ TASK MANAGER STYLE: Performance thresholds
        self.high_cpu_threshold = 50.0  # 50% CPU usage
        self.high_memory_threshold = 100  # 100MB memory usage
        
        # ✅ TASK MANAGER STYLE: Suspicious process patterns
        self.suspicious_patterns = [
            'backdoor', 'trojan', 'malware', 'virus', 'rootkit',
            'keylogger', 'spyware', 'crypto', 'miner', 'botnet'
        ]
        
        self.logger.info("✅ Enhanced Linux Process Collector initialized")
        self.logger.info("🐧 Task Manager Style Process Collector initialized")
        self.logger.info(f"   ⏱ Polling Interval: {self.polling_interval}s (Real-time)")
        self.logger.info(f"   📊 Max Events/Batch: {self.max_events_per_batch}")
        self.logger.info(f"   🔄 Continuous Mode: All Processes")
        self.logger.info(f"   📡 Real-time Streaming: No Delays")
        self.logger.info(f"   🎯 Task Manager Style: Comprehensive Monitoring")
    
    async def _collect_data(self):
        """✅ TASK MANAGER STYLE: Collect and send process events immediately"""
        try:
            start_time = time.time()
            events = []
            current_pids = set()
            
            # ✅ TASK MANAGER STYLE: Rate limiting check
            if not self._check_rate_limit():
                self.logger.debug("Rate limit reached, skipping collection")
                return []
            
            # Get current processes with comprehensive information
            try:
                filtered_processes = 0
                total_processes = 0
                
                # ✅ TASK MANAGER STYLE: Get detailed process information
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                               'username', 'ppid', 'status', 'cpu_percent', 'memory_info',
                                               'num_threads', 'num_fds', 'connections', 'open_files']):
                    try:
                        total_processes += 1
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        if not pid or not proc_info.get('name'):
                            filtered_processes += 1
                            continue
                        
                        # ✅ TASK MANAGER STYLE: Apply minimal filtering
                        if self._should_filter_process(proc_info):
                            filtered_processes += 1
                            continue
                        
                        current_pids.add(pid)
                        
                        # ✅ TASK MANAGER STYLE: Check for new process
                        if pid not in self.monitored_processes:
                            event = await self._create_process_start_event(proc_info)
                            if event and self._is_event_worth_sending(event):
                                await self._send_event_immediately(event)
                                events.append(event)
                                self.stats['process_creation_events'] += 1
                                self._increment_event_count()
                                
                                # Log new process
                                agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                                self.logger.info(f"🐧 Linux Process Event: New - Agent: {agent_id_short}...")
                        
                        # ✅ TASK MANAGER STYLE: Check for process updates (CPU, Memory, etc.)
                        else:
                            old_info = self.monitored_processes[pid]
                            if self._has_process_changed(proc_info, old_info):
                                event = await self._create_process_update_event(proc_info, old_info)
                                if event and self._is_event_worth_sending(event):
                                    await self._send_event_immediately(event)
                                    events.append(event)
                                    self.stats['process_update_events'] += 1
                                    self._increment_event_count()
                                    
                                    # Log process update
                                    agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                                    self.logger.info(f"🐧 Linux Process Event: Update - Agent: {agent_id_short}...")
                        
                        # ✅ TASK MANAGER STYLE: Check for high resource usage
                        if self._is_high_resource_process(proc_info):
                            event = await self._create_high_resource_event(proc_info)
                            if event and self._is_event_worth_sending(event):
                                await self._send_event_immediately(event)
                                events.append(event)
                                self._increment_event_count()
                                
                                # Log high resource usage
                                agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                                self.logger.info(f"🐧 Linux Process Event: High Resource - Agent: {agent_id_short}...")
                                    
                        # ✅ TASK MANAGER STYLE: Check for suspicious processes
                        if self._is_suspicious_process(proc_info):
                            event = await self._create_suspicious_process_event(proc_info)
                            if event and self._is_event_worth_sending(event):
                                await self._send_event_immediately(event)
                                events.append(event)
                                self.stats['suspicious_processes'] += 1
                                self._increment_event_count()
                                
                                # Log suspicious process
                                agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                                self.logger.info(f"🐧 Linux Process Event: Suspicious - Agent: {agent_id_short}...")
                        
                        # ✅ TASK MANAGER STYLE: Update tracking with comprehensive data
                        self.monitored_processes[pid] = {
                            'name': proc_info.get('name'),
                            'exe': proc_info.get('exe'),
                            'cmdline': proc_info.get('cmdline', []),
                            'create_time': proc_info.get('create_time'),
                            'username': proc_info.get('username'),
                            'ppid': proc_info.get('ppid'),
                            'status': proc_info.get('status'),
                            'cpu_percent': proc_info.get('cpu_percent', 0),
                            'memory_mb': self._get_memory_mb(proc_info.get('memory_info')),
                            'num_threads': proc_info.get('num_threads', 0),
                            'num_fds': proc_info.get('num_fds', 0),
                            'last_seen': time.time(),
                            'category': self._get_process_category(proc_info.get('name', ''))
                        }
                        
                        # ✅ TASK MANAGER STYLE: Stop if we hit batch limit
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
            
            # ✅ TASK MANAGER STYLE: Process terminations
            if len(events) < self.max_events_per_batch:
                terminated_pids = self.last_scan_pids - current_pids
                for pid in list(terminated_pids)[:5]:  # Limit to 5 termination events
                    if pid in self.monitored_processes:
                        proc_data = self.monitored_processes[pid]
                        event = await self._create_process_end_event(pid, proc_data)
                        if event and self._is_event_worth_sending(event):
                            await self._send_event_immediately(event)
                            events.append(event)
                            self.stats['process_termination_events'] += 1
                            self._increment_event_count()
                            
                        # Log process termination
                        agent_id_short = self.agent_id[:8] if self.agent_id else 'unknown'
                        self.logger.info(f"🐧 Linux Process Event: Terminated - Agent: {agent_id_short}...")
                        del self.monitored_processes[pid]
            
            # Update tracking
            self.last_scan_pids = current_pids
            self.stats['total_process_events'] += len(events)
            self.stats['filtered_events'] += filtered_processes
            
            # ✅ TASK MANAGER STYLE: Log collection efficiency
            collection_time = (time.time() - start_time) * 1000
            if events:
                self.logger.info(f"🐧 Generated {len(events)} process events ({collection_time:.1f}ms)")
                self.logger.debug(f"   📊 Filtered {filtered_processes}/{total_processes} processes")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Process collection failed: {e}")
            return []
    
    def _should_filter_process(self, proc_info: Dict) -> bool:
        """✅ TASK MANAGER STYLE: Minimal filtering - monitor everything"""
        try:
            name = proc_info.get('name', '').lower()
            status = proc_info.get('status', '')
            
            # Only filter zombie/dead processes
            if status in ['zombie', 'dead']:
                return True
            
            # Filter our own agent processes to avoid spam
            cmdline = proc_info.get('cmdline', [])
            if cmdline:
                cmdline_str = ' '.join(cmdline).lower()
                if any(agent_term in cmdline_str for agent_term in ['edr-agent', 'python3 main.py', 'agent_daemon.py']):
                    return True
            
            return False
            
        except Exception:
            return True  # Filter on error
    
    def _has_process_changed(self, new_info: Dict, old_info: Dict) -> bool:
        """✅ TASK MANAGER STYLE: Check if process has significant changes"""
        try:
            # Check CPU usage change
            new_cpu = new_info.get('cpu_percent', 0)
            old_cpu = old_info.get('cpu_percent', 0)
            if abs(new_cpu - old_cpu) > 10:  # 10% CPU change
                return True
            
            # Check memory usage change
            new_memory = self._get_memory_mb(new_info.get('memory_info'))
            old_memory = old_info.get('memory_mb', 0)
            if abs(new_memory - old_memory) > 10:  # 10MB memory change
                return True
            
            # Check status change
            new_status = new_info.get('status', '')
            old_status = old_info.get('status', '')
            if new_status != old_status:
                return True
            
            # Check thread count change
            new_threads = new_info.get('num_threads', 0)
            old_threads = old_info.get('num_threads', 0)
            if new_threads != old_threads:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_high_resource_process(self, proc_info: Dict) -> bool:
        """✅ TASK MANAGER STYLE: Check if process uses high resources"""
        try:
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_mb = self._get_memory_mb(proc_info.get('memory_info'))
            
            if cpu_percent > self.high_cpu_threshold:
                self.stats['high_cpu_processes'] += 1
                return True
            
            if memory_mb > self.high_memory_threshold:
                self.stats['high_memory_processes'] += 1
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_suspicious_process(self, proc_info: Dict) -> bool:
        """✅ TASK MANAGER STYLE: Check if process is suspicious"""
        try:
            name = proc_info.get('name', '').lower()
            cmdline = proc_info.get('cmdline', [])
            exe = proc_info.get('exe', '')
            
            # Check name for suspicious patterns
            if any(pattern in name for pattern in self.suspicious_patterns):
                return True
            
            # Check command line for suspicious patterns
            if cmdline:
                cmdline_str = ' '.join(cmdline).lower()
                if any(pattern in cmdline_str for pattern in self.suspicious_patterns):
                    return True
            
            # Check executable path for suspicious patterns
            if exe and any(pattern in exe.lower() for pattern in self.suspicious_patterns):
                return True
            
            return False
            
        except Exception:
            return False
    
    def _get_process_category(self, process_name: str) -> str:
        """✅ TASK MANAGER STYLE: Get process category"""
        if not process_name:
            return 'unknown'
        
        process_lower = process_name.lower()
        for category, processes in self.process_categories.items():
            if any(proc.lower() in process_lower for proc in processes):
                return category
        return 'other'
    
    async def _create_process_start_event(self, proc_info: Dict) -> Optional[EventData]:
        """✅ TASK MANAGER STYLE: Create comprehensive process start event"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create process event - missing agent_id")
                return None
            
            # Extract comprehensive process information
            pid = proc_info.get('pid')
            name = proc_info.get('name', 'Unknown')
            exe = proc_info.get('exe')
            cmdline = proc_info.get('cmdline', [])
            username = proc_info.get('username')
            ppid = proc_info.get('ppid')
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_info = proc_info.get('memory_info')
            num_threads = proc_info.get('num_threads', 0)
            num_fds = proc_info.get('num_fds', 0)
            
            # Ensure proper data types
            if pid is not None:
                pid = int(pid)
            else:
                self.logger.error(f"❌ Cannot create process event - pid is None")
                return None
            if ppid is not None:
                ppid = int(ppid)
            
            # Create command line string safely
            cmdline_str = ""
            if cmdline and isinstance(cmdline, list):
                cmdline_str = ' '.join(str(arg) for arg in cmdline[:10])  # Limit to first 10 args
            elif isinstance(cmdline, str):
                cmdline_str = cmdline[:500]  # Limit length
            
            # Determine severity
            severity = "Info"
            if self._is_high_resource_process(proc_info):
                severity = "Medium"
            if self._is_suspicious_process(proc_info):
                severity = "High"
            
            # Create comprehensive event
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
                
                description=f"Linux Process Started: {name} (PID: {pid}, User: {username})",
                
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'is_interesting': self._is_interesting_process(name),
                    'is_high_resource': self._is_high_resource_process(proc_info),
                    'is_suspicious': self._is_suspicious_process(proc_info),
                    'create_time': proc_info.get('create_time'),
                    'monitoring_method': 'task_manager_style',
                    'cpu_percent': cpu_percent,
                    'memory_mb': self._get_memory_mb(memory_info),
                    'num_threads': num_threads,
                    'num_fds': num_fds,
                    'status': proc_info.get('status', 'running'),
                    'scan_timestamp': time.time()
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
    
    async def _create_process_update_event(self, proc_info: Dict, old_info: Dict) -> Optional[EventData]:
        """✅ TASK MANAGER STYLE: Create process update event"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create process update event - missing agent_id")
                return None
            
            pid = proc_info.get('pid')
            name = proc_info.get('name', 'Unknown')
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_mb = self._get_memory_mb(proc_info.get('memory_info'))
            num_threads = proc_info.get('num_threads', 0)
            
            # Calculate changes
            old_cpu = old_info.get('cpu_percent', 0)
            old_memory = old_info.get('memory_mb', 0)
            old_threads = old_info.get('num_threads', 0)
            
            cpu_change = cpu_percent - old_cpu
            memory_change = memory_mb - old_memory
            thread_change = num_threads - old_threads
            
            # Determine severity based on changes
            severity = "Info"
            if abs(cpu_change) > 20 or abs(memory_change) > 50:
                severity = "Medium"
            
            event = EventData(
                event_type="Process",
                event_action="Update",
                severity=severity,
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                process_id=pid,
                process_name=name,
                
                description=f"Linux Process Updated: {name} (PID: {pid}) - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.1f}MB",
                
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'monitoring_method': 'task_manager_style',
                    'cpu_percent': cpu_percent,
                    'memory_mb': memory_mb,
                    'num_threads': num_threads,
                    'cpu_change': cpu_change,
                    'memory_change': memory_change,
                    'thread_change': thread_change,
                    'update_timestamp': time.time()
                }
            )
            
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid process update event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Process update event creation failed: {e}")
            return None
    
    async def _create_high_resource_event(self, proc_info: Dict) -> Optional[EventData]:
        """✅ TASK MANAGER STYLE: Create high resource usage event"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create high resource event - missing agent_id")
                return None
            
            pid = proc_info.get('pid')
            name = proc_info.get('name', 'Unknown')
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_mb = self._get_memory_mb(proc_info.get('memory_info'))
            
            # Ensure pid is valid
            if pid is None:
                self.logger.error(f"❌ Cannot create high resource event - pid is None")
                return None
            
            event = EventData(
                event_type="Process",
                event_action="High_Resource",
                severity="Medium",
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                process_id=int(pid),
                process_name=name,
                
                description=f"High Resource Usage: {name} (PID: {pid}) - CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.1f}MB",
                
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'monitoring_method': 'task_manager_style',
                    'cpu_percent': cpu_percent,
                    'memory_mb': memory_mb,
                    'high_cpu_threshold': self.high_cpu_threshold,
                    'high_memory_threshold': self.high_memory_threshold,
                    'resource_timestamp': time.time()
                }
            )
            
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid high resource event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ High resource event creation failed: {e}")
            return None
    
    async def _create_suspicious_process_event(self, proc_info: Dict) -> Optional[EventData]:
        """✅ TASK MANAGER STYLE: Create suspicious process event"""
        try:
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create suspicious process event - missing agent_id")
                return None
            
            pid = proc_info.get('pid')
            name = proc_info.get('name', 'Unknown')
            cmdline = proc_info.get('cmdline', [])
            exe = proc_info.get('exe', '')
            
            # Ensure pid is valid
            if pid is None:
                self.logger.error(f"❌ Cannot create suspicious process event - pid is None")
                return None
            
            cmdline_str = ""
            if cmdline and isinstance(cmdline, list):
                cmdline_str = ' '.join(str(arg) for arg in cmdline[:10])
            
            event = EventData(
                event_type="Process",
                event_action="Suspicious",
                severity="High",
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                process_id=int(pid),
                process_name=name,
                process_path=exe,
                command_line=cmdline_str,
                
                description=f"Suspicious Process Detected: {name} (PID: {pid})",
                
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'monitoring_method': 'task_manager_style',
                    'suspicious_patterns': self.suspicious_patterns,
                    'detection_timestamp': time.time()
                }
            )
            
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid suspicious process event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Suspicious process event creation failed: {e}")
            return None
    
    def _is_interesting_process(self, process_name: str) -> bool:
        """Check if process is interesting for security monitoring"""
        if not process_name:
            return False
        
        process_lower = process_name.lower()
        for category, processes in self.process_categories.items():
            if any(proc.lower() in process_lower for proc in processes):
                return True
        return False
    
    def _check_rate_limit(self) -> bool:
        """✅ TASK MANAGER STYLE: Check if we're within rate limits"""
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
        """✅ TASK MANAGER STYLE: Check if event is worth sending"""
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
    
    def _get_memory_mb(self, memory_info):
        """✅ FIXED: Properly handle psutil memory_info object"""
        try:
            if memory_info and hasattr(memory_info, 'rss'):
                return memory_info.rss / 1024 / 1024  # Convert bytes to MB
            return 0
        except Exception:
            return 0
    
    async def _send_event_immediately(self, event: EventData):
        """✅ TASK MANAGER STYLE: Send event immediately to event processor"""
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
        """✅ TASK MANAGER STYLE: Get detailed process collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Enhanced_Linux_Process_TaskManager',
            'process_creation_events': self.stats['process_creation_events'],
            'process_termination_events': self.stats['process_termination_events'],
            'process_running_events': self.stats['process_running_events'],
            'process_update_events': self.stats['process_update_events'],
            'interesting_process_events': self.stats['interesting_process_events'],
            'total_process_events': self.stats['total_process_events'],
            'filtered_events': self.stats['filtered_events'],
            'rate_limited_events': self.stats['rate_limited_events'],
            'high_cpu_processes': self.stats['high_cpu_processes'],
            'high_memory_processes': self.stats['high_memory_processes'],
            'suspicious_processes': self.stats['suspicious_processes'],
            'monitored_processes_count': len(self.monitored_processes),
            'process_categories': list(self.process_categories.keys()),
            'high_cpu_threshold': self.high_cpu_threshold,
            'high_memory_threshold': self.high_memory_threshold,
            'max_events_per_minute': self.max_events_per_minute,
            'events_this_minute': self.events_this_minute,
            'task_manager_style': True,
            'enhancement_version': '2.1.0-TaskManagerStyle'
        })
        return base_stats

    async def _collection_loop(self):
        """✅ TASK MANAGER STYLE: Continuous collection loop with real-time updates"""
        self.logger.info(f"🔄 Starting Enhanced Linux collection loop: {self.collector_name}")
        
        try:
            while self.is_running:
                try:
                    # ✅ TASK MANAGER STYLE: Collect data immediately
                    events = await self._collect_data()
                    
                    # ✅ TASK MANAGER STYLE: Send events immediately
                    if events:
                        for event in events:
                            await self._send_event_immediately(event)
                            self.logger.info(f"📡 Task Manager Event Sent: {event.process_name}")
            
                    # ✅ TASK MANAGER STYLE: Very short sleep for real-time monitoring
                    await asyncio.sleep(self.polling_interval)
                    
                except asyncio.CancelledError:
                    self.logger.info(f"🛑 Collection loop cancelled: {self.collector_name}")
                    break
                except Exception as e:
                    self.logger.error(f"❌ Collection loop error: {e}")
                    await asyncio.sleep(1)  # Short delay on error
                    
        except Exception as e:
            self.logger.error(f"❌ Collection loop failed: {e}")
        finally:
            self.logger.info(f"🛑 Collection loop stopped: {self.collector_name}")

    async def start(self):
        """✅ TASK MANAGER STYLE: Start enhanced process collector with real-time monitoring"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info(f"🚀 Starting Enhanced Linux collector: {self.collector_name}")
            
            # ✅ TASK MANAGER STYLE: Start our custom collection loop
            asyncio.create_task(self._collection_loop())
            
            self.logger.info(f"✅ Enhanced Linux collector started: {self.collector_name}")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} start failed: {e}")
            self.is_running = False
            raise Exception(f"Enhanced Linux collector start failed: {e}")
    
    async def _create_process_end_event(self, pid: int, proc_info: Dict) -> Optional[EventData]:
        """✅ TASK MANAGER STYLE: Create process end event"""
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
                    'monitoring_method': 'task_manager_style'
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
    
# Backward compatibility alias
LinuxProcessCollector = EnhancedLinuxProcessCollector