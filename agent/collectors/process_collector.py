# agent/collectors/process_collector.py - Linux Process Collector
"""
Linux Process Collector - Monitor processes using /proc filesystem and psutil
Optimized for Linux process monitoring with enhanced capabilities
"""

import psutil
import os
import time
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
from collections import defaultdict

from agent.collectors.base_collector import LinuxBaseCollector
from agent.schemas.events import EventData, EventAction

class LinuxProcessCollector(LinuxBaseCollector):
    """Linux Process Collector with /proc filesystem monitoring"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "LinuxProcessCollector")
        
        # Linux process monitoring settings
        self.polling_interval = 2.0  # 2 seconds for process monitoring
        self.max_events_per_batch = 15
        
        # Process tracking
        self.monitored_processes = {}  # pid -> process_info
        self.last_scan_pids = set()
        self.process_cpu_history = defaultdict(list)
        self.process_memory_history = defaultdict(list)
        
        # Linux-specific process categories
        self.interesting_processes = {
            'shells': ['bash', 'sh', 'zsh', 'fish', 'csh', 'tcsh'],
            'editors': ['vim', 'nano', 'emacs', 'gedit', 'code'],
            'system_tools': ['sudo', 'su', 'systemctl', 'service'],
            'network_tools': ['ssh', 'scp', 'rsync', 'wget', 'curl'],
            'development': ['python', 'python3', 'node', 'java', 'gcc', 'make'],
            'containers': ['docker', 'podman', 'lxc'],
            'security': ['gpg', 'openssl', 'passwd', 'usermod'],
            'monitoring': ['top', 'htop', 'ps', 'netstat', 'ss']
        }
        
        # Process filtering
        self.exclude_kernel_threads = True
        self.exclude_short_lived = True  # Exclude processes that live < 1 second
        
        # Performance thresholds
        self.high_cpu_threshold = 80
        self.high_memory_threshold = 500 * 1024 * 1024  # 500MB
        
        # Statistics
        self.stats = {
            'process_creation_events': 0,
            'process_termination_events': 0,
            'high_cpu_events': 0,
            'high_memory_events': 0,
            'interesting_process_events': 0,
            'total_process_events': 0
        }
        
        self.logger.info("🐧 Linux Process Collector initialized")
    
    async def _check_collector_requirements(self):
        """Check Linux process monitoring requirements"""
        try:
            # Check if we can read /proc
            if not os.access('/proc', os.R_OK):
                raise Exception("Cannot access /proc filesystem")
            
            # Check if we can read process information
            test_paths = ['/proc/self/stat', '/proc/self/status', '/proc/self/cmdline']
            for path in test_paths:
                if not os.access(path, os.R_OK):
                    self.logger.warning(f"⚠️ Cannot read {path}")
            
            # Test psutil functionality
            try:
                list(psutil.process_iter(['pid', 'name']))
                self.logger.info("✅ psutil process monitoring available")
            except Exception as e:
                self.logger.warning(f"⚠️ psutil limited functionality: {e}")
                
        except Exception as e:
            self.logger.error(f"❌ Process collector requirements check failed: {e}")
            raise
    
    async def _collect_data(self):
        """Collect Linux process events"""
        try:
            start_time = time.time()
            events = []
            current_pids = set()
            
            # Get current processes using psutil
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                               'username', 'ppid', 'status', 'cpu_percent', 'memory_info']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        # Skip if no PID or name
                        if not pid or not proc_info.get('name'):
                            continue
                        
                        # Filter kernel threads if enabled
                        if self.exclude_kernel_threads and self._is_kernel_thread(proc_info):
                            continue
                        
                        current_pids.add(pid)
                        
                        # Get additional Linux-specific information
                        proc_info = await self._enhance_process_info(proc_info)
                        
                        # Check for new process
                        if pid not in self.monitored_processes:
                            # Skip very short-lived processes if configured
                            if self.exclude_short_lived:
                                create_time = proc_info.get('create_time', 0)
                                if create_time > 0 and (time.time() - create_time) < 1.0:
                                    continue
                            
                            event = await self._create_process_start_event(proc_info)
                            if event:
                                events.append(event)
                                self.stats['process_creation_events'] += 1
                        
                        # Check for interesting process activity
                        if self._is_interesting_process(proc_info.get('name', '')):
                            if pid not in self.monitored_processes:
                                event = await self._create_interesting_process_event(proc_info)
                                if event:
                                    events.append(event)
                                    self.stats['interesting_process_events'] += 1
                        
                        # Check for high resource usage
                        events.extend(await self._check_resource_usage(proc_info))
                        
                        # Update process tracking
                        self.monitored_processes[pid] = {
                            'name': proc_info.get('name'),
                            'exe': proc_info.get('exe'),
                            'cmdline': proc_info.get('cmdline'),
                            'username': proc_info.get('username'),
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
                    event = await self._create_process_end_event(pid, self.monitored_processes[pid])
                    if event:
                        events.append(event)
                        self.stats['process_termination_events'] += 1
                    del self.monitored_processes[pid]
            
            # Update tracking
            self.last_scan_pids = current_pids
            self.stats['total_process_events'] += len(events)
            
            # Log collection performance
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 2000:  # 2 seconds
                self.logger.warning(f"⚠️ Slow process collection: {collection_time:.1f}ms")
            elif events:
                self.logger.info(f"🐧 Generated {len(events)} process events ({collection_time:.1f}ms)")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Process collection failed: {e}")
            return []
    
    async def _enhance_process_info(self, proc_info: Dict) -> Dict:
        """Enhance process info with Linux-specific details"""
        try:
            pid = proc_info.get('pid')
            if not pid:
                return proc_info
            
            # Get additional info from /proc
            proc_path = f'/proc/{pid}'
            
            # Read command line from /proc/PID/cmdline
            cmdline_path = f'{proc_path}/cmdline'
            if os.path.exists(cmdline_path):
                try:
                    with open(cmdline_path, 'rb') as f:
                        cmdline_raw = f.read().decode('utf-8', errors='ignore')
                        cmdline_list = cmdline_raw.split('\x00')[:-1]  # Remove empty last element
                        if cmdline_list:
                            proc_info['cmdline_enhanced'] = cmdline_list
                            proc_info['cmdline_string'] = ' '.join(cmdline_list)
                except:
                    pass
            
            # Read environment variables (if accessible)
            environ_path = f'{proc_path}/environ'
            if os.path.exists(environ_path) and self.has_required_privileges:
                try:
                    with open(environ_path, 'rb') as f:
                        environ_raw = f.read().decode('utf-8', errors='ignore')
                        environ_vars = {}
                        for env_var in environ_raw.split('\x00'):
                            if '=' in env_var:
                                key, value = env_var.split('=', 1)
                                environ_vars[key] = value
                        proc_info['environment_vars'] = environ_vars
                except:
                    pass
            
            # Get file descriptor count
            fd_path = f'{proc_path}/fd'
            if os.path.exists(fd_path):
                try:
                    fd_count = len(os.listdir(fd_path))
                    proc_info['fd_count'] = fd_count
                except:
                    proc_info['fd_count'] = 0
            
            # Get process status details
            try:
                status_info = self.parse_proc_status(pid)
                if status_info:
                    proc_info['proc_status'] = status_info
                    # Extract useful fields
                    proc_info['threads'] = status_info.get('Threads', '1')
                    proc_info['vm_size'] = status_info.get('VmSize', '0')
                    proc_info['vm_rss'] = status_info.get('VmRSS', '0')
            except:
                pass
            
            return proc_info
            
        except Exception as e:
            self.logger.debug(f"Error enhancing process info: {e}")
            return proc_info
    
    def _is_kernel_thread(self, proc_info: Dict) -> bool:
        """Check if process is a kernel thread"""
        try:
            name = proc_info.get('name', '')
            exe = proc_info.get('exe')
            
            # Kernel threads typically have names in brackets
            if name.startswith('[') and name.endswith(']'):
                return True
            
            # Kernel threads usually don't have executable paths
            if not exe:
                return True
            
            # Check for common kernel thread names
            kernel_thread_names = [
                'kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog',
                'kworker', 'kblockd', 'kdevtmpfs', 'netns', 'kauditd'
            ]
            
            for kernel_name in kernel_thread_names:
                if kernel_name in name:
                    return True
            
            return False
            
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
        """Get process category for classification"""
        if not process_name:
            return 'unknown'
        
        process_lower = process_name.lower()
        
        for category, processes in self.interesting_processes.items():
            if any(proc.lower() in process_lower for proc in processes):
                return category
        
        return 'other'
    
    async def _check_resource_usage(self, proc_info: Dict) -> List[EventData]:
        """Check for high resource usage"""
        events = []
        
        try:
            pid = proc_info.get('pid')
            if not pid:
                return events
            
            # Check CPU usage
            cpu_percent = proc_info.get('cpu_percent', 0)
            if cpu_percent > self.high_cpu_threshold:
                event = await self._create_high_cpu_event(proc_info, cpu_percent)
                if event:
                    events.append(event)
                    self.stats['high_cpu_events'] += 1
            
            # Check memory usage
            memory_info = proc_info.get('memory_info')
            if memory_info and hasattr(memory_info, 'rss'):
                memory_rss = memory_info.rss
                if memory_rss > self.high_memory_threshold:
                    event = await self._create_high_memory_event(proc_info, memory_rss)
                    if event:
                        events.append(event)
                        self.stats['high_memory_events'] += 1
        
        except Exception as e:
            self.logger.debug(f"Error checking resource usage: {e}")
        
        return events
    
    async def _create_process_start_event(self, proc_info: Dict):
        """Create process start event"""
        try:
            process_name = proc_info.get('name', 'Unknown')
            severity = self._determine_process_severity(proc_info)
            
            # Get enhanced command line
            cmdline = proc_info.get('cmdline_string') or ' '.join(proc_info.get('cmdline', []))
            
            return EventData(
                event_type="Process",
                event_action=EventAction.START,
                event_timestamp=datetime.now(),
                severity=severity,
                
                process_id=proc_info.get('pid'),
                process_name=process_name,
                process_path=proc_info.get('exe'),
                command_line=cmdline,
                parent_pid=proc_info.get('ppid'),
                process_user=proc_info.get('username'),
                
                description=f"🐧 LINUX PROCESS STARTED: {process_name} (PID: {proc_info.get('pid')})",
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(process_name),
                    'is_interesting': self._is_interesting_process(process_name),
                    'fd_count': proc_info.get('fd_count', 0),
                    'threads': proc_info.get('threads', '1'),
                    'vm_size': proc_info.get('vm_size', '0'),
                    'create_time': proc_info.get('create_time'),
                    'proc_status': proc_info.get('proc_status', {}),
                    'cmdline_enhanced': proc_info.get('cmdline_enhanced', []),
                    'monitoring_method': 'psutil_proc_iter'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Process start event creation failed: {e}")
            return None
    
    async def _create_process_end_event(self, pid: int, proc_info: Dict):
        """Create process termination event"""
        try:
            process_name = proc_info.get('name', 'Unknown')
            
            # Calculate process lifetime
            create_time = proc_info.get('create_time', 0)
            last_seen = proc_info.get('last_seen', time.time())
            lifetime = last_seen - create_time if create_time > 0 else 0
            
            return EventData(
                event_type="Process",
                event_action=EventAction.STOP,
                event_timestamp=datetime.now(),
                severity="Info",
                
                process_id=pid,
                process_name=process_name,
                process_path=proc_info.get('exe'),
                process_user=proc_info.get('username'),
                
                description=f"🐧 LINUX PROCESS ENDED: {process_name} (PID: {pid}, ran {lifetime:.1f}s)",
                raw_event_data={
                    'platform': 'linux',
                    'process_category': self._get_process_category(process_name),
                    'termination_time': time.time(),
                    'process_lifetime': lifetime,
                    'was_interesting': self._is_interesting_process(process_name),
                    'last_cmdline': proc_info.get('cmdline'),
                    'monitoring_method': 'psutil_process_tracking'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Process end event creation failed: {e}")
            return None
    
    async def _create_interesting_process_event(self, proc_info: Dict):
        """Create interesting process activity event"""
        try:
            process_name = proc_info.get('name', 'Unknown')
            category = self._get_process_category(process_name)
            
            return EventData(
                event_type="Process",
                event_action=EventAction.ACCESS,
                event_timestamp=datetime.now(),
                severity="Medium" if category in ['system_tools', 'security'] else "Info",
                
                process_id=proc_info.get('pid'),
                process_name=process_name,
                process_path=proc_info.get('exe'),
                command_line=proc_info.get('cmdline_string', ''),
                process_user=proc_info.get('username'),
                
                description=f"🐧 LINUX INTERESTING PROCESS: {process_name} ({category})",
                raw_event_data={
                    'platform': 'linux',
                    'process_category': category,
                    'activity_type': 'execution',
                    'interest_level': 'high' if category in ['system_tools', 'security'] else 'medium',
                    'environment_vars': proc_info.get('environment_vars', {}),
                    'fd_count': proc_info.get('fd_count', 0),
                    'threads': proc_info.get('threads', '1'),
                    'enhanced_monitoring': True
                }
            )
        except Exception as e:
            self.logger.error(f"❌ Interesting process event creation failed: {e}")
            return None
    
    async def _create_high_cpu_event(self, proc_info: Dict, cpu_percent: float):
        """Create high CPU usage event"""
        try:
            return EventData(
                event_type="Process",
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="High" if cpu_percent > 90 else "Medium",
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                cpu_usage=cpu_percent,
                process_user=proc_info.get('username'),
                
                description=f"🐧 LINUX HIGH CPU: {proc_info.get('name')} using {cpu_percent:.1f}% CPU",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'high_cpu_usage',
                    'cpu_percent': cpu_percent,
                    'threshold': self.high_cpu_threshold,
                    'performance_impact': 'high' if cpu_percent > 90 else 'medium',
                    'process_category': self._get_process_category(proc_info.get('name', '')),
                    'threads': proc_info.get('threads', '1'),
                    'monitoring_method': 'psutil_cpu_percent'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ High CPU event creation failed: {e}")
            return None
    
    async def _create_high_memory_event(self, proc_info: Dict, memory_rss: int):
        """Create high memory usage event"""
        try:
            memory_mb = memory_rss / (1024 * 1024)
            
            return EventData(
                event_type="Process",
                event_action=EventAction.RESOURCE_USAGE,
                event_timestamp=datetime.now(),
                severity="High" if memory_mb > 1000 else "Medium",
                
                process_id=proc_info.get('pid'),
                process_name=proc_info.get('name'),
                memory_usage=memory_mb,
                process_user=proc_info.get('username'),
                
                description=f"🐧 LINUX HIGH MEMORY: {proc_info.get('name')} using {memory_mb:.1f}MB",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'high_memory_usage',
                    'memory_rss': memory_rss,
                    'memory_mb': memory_mb,
                    'threshold_mb': self.high_memory_threshold / (1024 * 1024),
                    'vm_size': proc_info.get('vm_size', '0'),
                    'vm_rss': proc_info.get('vm_rss', '0'),
                    'process_category': self._get_process_category(proc_info.get('name', '')),
                    'monitoring_method': 'psutil_memory_info'
                }
            )
        except Exception as e:
            self.logger.error(f"❌ High memory event creation failed: {e}")
            return None
    
    def _determine_process_severity(self, proc_info: Dict) -> str:
        """Determine process severity based on Linux-specific factors"""
        try:
            process_name = proc_info.get('name', '').lower()
            cmdline = proc_info.get('cmdline_string', '').lower()
            username = proc_info.get('username', '')
            
            # Critical severity for security-sensitive processes
            if any(sec_proc in process_name for sec_proc in ['sudo', 'su', 'passwd', 'usermod']):
                return "Critical"
            
            # High severity for system administration
            if any(sys_proc in process_name for sys_proc in ['systemctl', 'service', 'mount', 'umount']):
                return "High"
            
            # High severity for network tools with suspicious usage
            if any(net_tool in process_name for net_tool in ['ssh', 'nc', 'netcat', 'socat']):
                return "High"
            
            # Medium severity for development and scripting
            if any(dev_proc in process_name for dev_proc in ['python', 'bash', 'sh', 'perl', 'ruby']):
                return "Medium"
            
            # Medium severity for interesting categories
            category = self._get_process_category(process_name)
            if category in ['system_tools', 'security', 'network_tools']:
                return "Medium"
            
            # High severity if running as root but not system process
            if username == 'root' and not self._is_system_process(process_name):
                return "High"
            
            return "Info"
            
        except Exception:
            return "Info"
    
    def _is_system_process(self, process_name: str) -> bool:
        """Check if process is a system process"""
        system_processes = {
            'systemd', 'kernel', 'kthreadd', 'ksoftirqd', 'migration',
            'rcu_', 'watchdog', 'sshd', 'dbus', 'networkmanager',
            'chronyd', 'rsyslog', 'cron', 'systemd-'
        }
        
        process_lower = process_name.lower()
        return any(sys_proc in process_lower for sys_proc in system_processes)
    
    def get_stats(self) -> Dict:
        """Get detailed Linux process collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Linux_Process',
            'process_creation_events': self.stats['process_creation_events'],
            'process_termination_events': self.stats['process_termination_events'],
            'high_cpu_events': self.stats['high_cpu_events'],
            'high_memory_events': self.stats['high_memory_events'],
            'interesting_process_events': self.stats['interesting_process_events'],
            'total_process_events': self.stats['total_process_events'],
            'monitored_processes_count': len(self.monitored_processes),
            'exclude_kernel_threads': self.exclude_kernel_threads,
            'exclude_short_lived': self.exclude_short_lived,
            'high_cpu_threshold': self.high_cpu_threshold,
            'high_memory_threshold_mb': self.high_memory_threshold / (1024 * 1024),
            'interesting_categories': list(self.interesting_processes.keys()),
            'linux_enhanced_monitoring': True
        })
        return base_stats