# agent/collectors/process_collector.py - FIXED Process Collector
"""
COMPLETELY FIXED Linux Process Collector
All event creation issues resolved with proper validation
"""

import psutil
import os
import time
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict

from agent.collectors.base_collector import LinuxBaseCollector
from agent.schemas.events import EventData, create_linux_process_event

class LinuxProcessCollector(LinuxBaseCollector):
    """✅ COMPLETELY FIXED: Linux Process Collector with proper event creation"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "LinuxProcessCollector")
        
        # Monitoring settings
        self.polling_interval = 10.0  # Increased to reduce spam
        self.max_events_per_batch = 10  # Reduced to prevent overwhelming
        
        # Process tracking
        self.monitored_processes = {}
        self.last_scan_pids = set()
        
        # Linux-specific process filtering
        self.exclude_kernel_threads = True
        self.exclude_short_lived = True
        self.min_process_lifetime = 2.0  # 2 seconds minimum
        
        # Interesting processes for Linux
        self.interesting_processes = {
            'security': ['sudo', 'su', 'ssh', 'gpg'],
            'system': ['systemctl', 'service', 'mount'],
            'network': ['nc', 'netcat', 'wget', 'curl'],
            'development': ['python', 'python3', 'bash', 'sh']
        }
        
        # Performance thresholds
        self.high_cpu_threshold = 80
        self.high_memory_threshold = 500 * 1024 * 1024  # 500MB
        
        # Statistics
        self.stats = {
            'process_creation_events': 0,
            'process_termination_events': 0,
            'interesting_process_events': 0,
            'total_process_events': 0
        }
        
        self.logger.info("🐧 Fixed Linux Process Collector initialized")
    
    async def _collect_data(self):
        """✅ COMPLETELY FIXED: Collect process events with proper validation"""
        try:
            start_time = time.time()
            events = []
            current_pids = set()
            
            # Get current processes
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                               'username', 'ppid', 'status']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        if not pid or not proc_info.get('name'):
                            continue
                        
                        # Filter kernel threads
                        if self.exclude_kernel_threads and self._is_kernel_thread(proc_info):
                            continue
                        
                        current_pids.add(pid)
                        
                        # Check for new process
                        if pid not in self.monitored_processes:
                            # Filter short-lived processes
                            if self.exclude_short_lived:
                                create_time = proc_info.get('create_time', 0)
                                if create_time > 0 and (time.time() - create_time) < self.min_process_lifetime:
                                    continue
                            
                            # ✅ FIXED: Create process event with proper validation
                            event = await self._create_process_start_event(proc_info)
                            if event:
                                # ✅ CRITICAL: Validate event before adding
                                is_valid, error = event.validate_for_server()
                                if is_valid:
                                    events.append(event)
                                    self.stats['process_creation_events'] += 1
                                else:
                                    self.logger.warning(f"⚠️ Invalid process event: {error}")
                        
                        # Update tracking
                        self.monitored_processes[pid] = {
                            'name': proc_info.get('name'),
                            'create_time': proc_info.get('create_time'),
                            'last_seen': time.time()
                        }
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error processing process {pid}: {e}")
                        continue
            
            except Exception as e:
                self.logger.error(f"Error iterating processes: {e}")
                return []
            
            # Detect terminated processes
            terminated_pids = self.last_scan_pids - current_pids
            for pid in terminated_pids:
                if pid in self.monitored_processes:
                    # ✅ FIXED: Create termination event with proper validation
                    event = await self._create_process_end_event(pid, self.monitored_processes[pid])
                    if event:
                        # ✅ CRITICAL: Validate event before adding
                        is_valid, error = event.validate_for_server()
                        if is_valid:
                            events.append(event)
                            self.stats['process_termination_events'] += 1
                        else:
                            self.logger.warning(f"⚠️ Invalid termination event: {error}")
                    del self.monitored_processes[pid]
            
            # Update tracking
            self.last_scan_pids = current_pids
            
            # Limit events to prevent spam
            if len(events) > self.max_events_per_batch:
                self.logger.warning(f"⚠️ Too many process events ({len(events)}), limiting to {self.max_events_per_batch}")
                events = events[:self.max_events_per_batch]
            
            self.stats['total_process_events'] += len(events)
            
            # Log collection performance
            collection_time = (time.time() - start_time) * 1000
            if events:
                self.logger.info(f"🐧 Generated {len(events)} process events ({collection_time:.1f}ms)")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Process collection failed: {e}")
            return []
    
    def _is_kernel_thread(self, proc_info: Dict) -> bool:
        """Check if process is a kernel thread"""
        try:
            name = proc_info.get('name', '')
            exe = proc_info.get('exe')
            
            # Kernel threads have names in brackets
            if name.startswith('[') and name.endswith(']'):
                return True
            
            # Kernel threads don't have executable paths
            if not exe:
                return True
            
            # Check common kernel thread patterns
            kernel_patterns = ['kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog', 'kworker']
            return any(pattern in name for pattern in kernel_patterns)
            
        except Exception:
            return False
    
    def _is_interesting_process(self, process_name: str) -> bool:
        """Check if process is interesting for monitoring"""
        if not process_name:
            return False
        
        process_lower = process_name.lower()
        for category, processes in self.interesting_processes.items():
            if any(proc.lower() in process_lower for proc in processes):
                return True
        return False
    
    def _get_process_category(self, process_name: str) -> str:
        """Get process category"""
        if not process_name:
            return 'unknown'
        
        process_lower = process_name.lower()
        for category, processes in self.interesting_processes.items():
            if any(proc.lower() in process_lower for proc in processes):
                return category
        return 'other'
    
    async def _create_process_start_event(self, proc_info: Dict) -> Optional[EventData]:
        """✅ COMPLETELY FIXED: Create process start event with full validation"""
        try:
            # ✅ CRITICAL: Ensure agent_id is available
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
            
            # ✅ FIXED: Ensure proper data types
            if pid is not None:
                pid = int(pid)
            if ppid is not None:
                ppid = int(ppid)
            
            # ✅ FIXED: Create command line string safely
            cmdline_str = ""
            if cmdline and isinstance(cmdline, list):
                cmdline_str = ' '.join(str(arg) for arg in cmdline)
            elif isinstance(cmdline, str):
                cmdline_str = cmdline
            
            # ✅ FIXED: Determine severity based on process type
            severity = "Info"
            if self._is_interesting_process(name):
                severity = "Medium"
                self.stats['interesting_process_events'] += 1
            
            # ✅ FIXED: Create properly validated event
            event = EventData(
                # Required fields
                event_type="Process",
                event_action="Start",
                severity=severity,
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                # Process-specific fields
                process_id=pid,
                process_name=name,
                process_path=exe,
                command_line=cmdline_str,
                parent_pid=ppid,
                process_user=username,
                
                # Description
                description=f"Linux Process Started: {name} (PID: {pid})",
                
                # Raw event data
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'is_interesting': self._is_interesting_process(name),
                    'create_time': proc_info.get('create_time'),
                    'monitoring_method': 'psutil_proc_iter'
                }
            )
            
            # ✅ CRITICAL: Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid process event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Process start event creation failed: {e}")
            return None
    
    async def _create_process_end_event(self, pid: int, proc_info: Dict) -> Optional[EventData]:
        """✅ COMPLETELY FIXED: Create process end event with full validation"""
        try:
            # ✅ CRITICAL: Ensure agent_id is available
            if not self.agent_id:
                self.logger.error(f"❌ Cannot create process end event - missing agent_id")
                return None
            
            name = proc_info.get('name', 'Unknown')
            create_time = proc_info.get('create_time', 0)
            last_seen = proc_info.get('last_seen', time.time())
            
            # Calculate lifetime
            lifetime = last_seen - create_time if create_time > 0 else 0
            
            # ✅ FIXED: Create properly validated event
            event = EventData(
                # Required fields
                event_type="Process",
                event_action="Stop",
                severity="Info",
                agent_id=self.agent_id,
                event_timestamp=datetime.now(),
                
                # Process-specific fields
                process_id=int(pid),
                process_name=name,
                
                # Description
                description=f"Linux Process Ended: {name} (PID: {pid}, ran {lifetime:.1f}s)",
                
                # Raw event data
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(name),
                    'termination_time': time.time(),
                    'process_lifetime': lifetime,
                    'monitoring_method': 'psutil_process_tracking'
                }
            )
            
            # ✅ CRITICAL: Validate event before returning
            is_valid, error = event.validate_for_server()
            if not is_valid:
                self.logger.error(f"❌ Created invalid process end event: {error}")
                return None
            
            return event
            
        except Exception as e:
            self.logger.error(f"❌ Process end event creation failed: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get process collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Linux_Process',
            'process_creation_events': self.stats['process_creation_events'],
            'process_termination_events': self.stats['process_termination_events'],
            'interesting_process_events': self.stats['interesting_process_events'],
            'total_process_events': self.stats['total_process_events'],
            'monitored_processes_count': len(self.monitored_processes),
            'exclude_kernel_threads': self.exclude_kernel_threads,
            'exclude_short_lived': self.exclude_short_lived,
            'min_process_lifetime': self.min_process_lifetime,
            'interesting_categories': list(self.interesting_processes.keys())
        })
        return base_stats