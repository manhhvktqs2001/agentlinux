# agent/collectors/file_collector.py - FIXED Linux File Collector
"""
Linux File Collector - FIXED VERSION
Monitor file system using inotify with proper event handling
"""

import asyncio
import os
import time
import stat
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional
from collections import defaultdict

# Try to import inotify
try:
    from watchdog.observers import Observer as WatchdogObserver
    from watchdog.events import FileSystemEventHandler as WatchdogFileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    WatchdogObserver = None
    WatchdogFileSystemEventHandler = None
    FileSystemEvent = None

# Dummy base classes for fallback
class DummyFileSystemEventHandler(object):
    pass
class DummyObserver(object):
    @staticmethod
    def start(): pass
    @staticmethod
    def stop(): pass
    @staticmethod
    def join(timeout=None): pass
    @staticmethod
    def schedule(*args, **kwargs): pass

# Always assign base classes (ensure never None and always a class)
def _get_valid_base_handler():
    if WATCHDOG_AVAILABLE and isinstance(WatchdogFileSystemEventHandler, type):
        return WatchdogFileSystemEventHandler
    return DummyFileSystemEventHandler
FileSystemEventHandler = _get_valid_base_handler()

if WATCHDOG_AVAILABLE and WatchdogObserver is not None:
    Observer = WatchdogObserver
else:
    Observer = DummyObserver

from agent.collectors.base_collector import LinuxBaseCollector
from agent.schemas.events import EventData

# Simple file event handler class
class LinuxFileEventHandler:
    """Linux file system event handler using inotify - FIXED VERSION"""
    def __init__(self, collector, loop):
        self.collector = collector
        self.logger = collector.logger
        self.loop = loop
        
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            try:
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.collector._handle_file_event('modified', event.src_path, ""),
                        self.loop
                    )
            except Exception as e:
                self.logger.error(f"❌ File event handling error: {e}")
                
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            try:
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.collector._handle_file_event('created', event.src_path, ""),
                        self.loop
                    )
            except Exception as e:
                self.logger.error(f"❌ File event handling error: {e}")
                
    def on_deleted(self, event):
        """Handle file deletion events"""
        if not event.is_directory:
            try:
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.collector._handle_file_event('deleted', event.src_path, ""),
                        self.loop
                    )
            except Exception as e:
                self.logger.error(f"❌ File event handling error: {e}")
                
    def on_moved(self, event):
        """Handle file move events"""
        if not event.is_directory:
            try:
                if self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.collector._handle_file_event('moved', event.dest_path, event.src_path),
                        self.loop
                    )
            except Exception as e:
                self.logger.error(f"❌ File move event handling error: {e}")


class LinuxFileCollector(LinuxBaseCollector):
    """Linux File Collector with inotify support - FIXED VERSION"""
    
    def __init__(self, config_manager=None):
        super().__init__(config_manager, "LinuxFileCollector")
        
        # Linux file monitoring settings
        self.polling_interval = 3.0  # 3 seconds for file scanning
        self.max_events_per_batch = 25
        
        # File monitoring paths (Linux-specific)
        self.monitor_paths = [
            '/home',           # User directories
            '/tmp',            # Temporary files
            '/var/tmp',        # Variable temporary files
            '/etc',            # Configuration files
            '/usr/local/bin',  # Local binaries
            '/usr/bin',        # System binaries
            '/bin',            # Essential binaries
            '/sbin',           # System binaries
            '/opt',            # Optional software
            '/var/log',        # Log files (if accessible)
        ]
        
        # File extensions to monitor
        self.interesting_extensions = {
            '.sh', '.bash', '.zsh',           # Shell scripts
            '.py', '.pl', '.rb', '.php',      # Scripts
            '.c', '.cpp', '.h',               # Source code
            '.conf', '.cfg', '.ini',          # Configuration files
            '.key', '.pem', '.crt',           # Security files
            '.sql', '.db',                    # Database files
            '.tar', '.gz', '.zip', '.7z',     # Archives
            ''                                # Executables without extension
        }
        
        # Suspicious file patterns
        self.suspicious_patterns = [
            'passwd', 'shadow', 'sudoers',    # System files
            '.ssh/', 'authorized_keys',       # SSH files
            'crontab', '.bash_history',       # User activity
            '.bashrc', '.profile',            # Shell configs
        ]
        
        # File tracking
        self.monitored_files = {}  # file_path -> file_info
        self.file_access_count = defaultdict(int)
        self.recent_file_events = {}  # For deduplication
        
        # inotify support
        self.observer = None
        self.event_handler = None
        self.inotify_enabled = WATCHDOG_AVAILABLE and self._check_inotify_support()
        
        # Performance settings
        self.large_file_threshold = 100 * 1024 * 1024  # 100MB
        self.max_files_per_scan = 500
        
        # Statistics
        self.stats = {
            'file_creation_events': 0,
            'file_modification_events': 0,
            'file_deletion_events': 0,
            'file_move_events': 0,
            'suspicious_file_events': 0,
            'large_file_events': 0,
            'total_file_events': 0,
            'inotify_events': 0,
            'scan_events': 0
        }
        
        self.logger.info(f"🐧 Linux File Collector initialized (inotify: {self.inotify_enabled})")
        
        # Save the main event loop for use in event handler
        try:
            self.loop = asyncio.get_running_loop()
        except RuntimeError:
            self.loop = asyncio.get_event_loop()
        
        self._tasks = []  # Quản lý các task async
    
    def _check_inotify_support(self) -> bool:
        """Check if inotify is supported on this system"""
        try:
            if not WATCHDOG_AVAILABLE:
                return False
            # Try to create a temporary observer
            if Observer is DummyObserver:
                Observer.start()
                Observer.stop()
                Observer.join(timeout=1)
            else:
                test_observer = Observer()
                test_observer.start()
                test_observer.stop()
                test_observer.join(timeout=1)
            return True
        except Exception as e:
            self.logger.warning(f"⚠️ inotify support check failed: {e}")
            return False
    
    async def _check_collector_requirements(self):
        """Check Linux file monitoring requirements"""
        try:
            # Check if we can access monitored paths
            accessible_paths = []
            for path in self.monitor_paths:
                if os.path.exists(path) and os.access(path, os.R_OK):
                    accessible_paths.append(path)
                else:
                    self.logger.warning(f"⚠️ Cannot access path: {path}")
            
            self.monitor_paths = accessible_paths
            self.logger.info(f"✅ Monitoring {len(self.monitor_paths)} accessible paths")
            
            # Check inotify limits if enabled
            if self.inotify_enabled:
                try:
                    with open('/proc/sys/fs/inotify/max_user_watches', 'r') as f:
                        max_watches = int(f.read().strip())
                        self.logger.info(f"✅ inotify max watches: {max_watches}")
                        
                        if max_watches < 8192:
                            self.logger.warning("⚠️ Low inotify watch limit may affect monitoring")
                except:
                    pass
                    
        except Exception as e:
            self.logger.error(f"❌ File collector requirements check failed: {e}")
            raise
    
    async def start(self):
        """Start Linux file monitoring with inotify"""
        await super().start()
        if self.inotify_enabled:
            try:
                # Setup inotify monitoring
                if Observer is DummyObserver:
                    self.observer = Observer
                else:
                    self.observer = Observer()
                self.event_handler = LinuxFileEventHandler(self, self.loop)
                # Add watches for monitored paths
                for path in self.monitor_paths:
                    if os.path.exists(path):
                        try:
                            if Observer is not DummyObserver:
                                self.observer.schedule(
                                    self.event_handler,
                                    path,
                                    recursive=True
                                )
                                self.logger.debug(f"Added inotify watch: {path}")
                        except Exception as e:
                            self.logger.warning(f"⚠️ Failed to watch {path}: {e}")
                if Observer is DummyObserver:
                    self.observer.start()
                else:
                    self.observer.start()
                self.logger.info("✅ Linux file monitoring started with inotify")
            except Exception as e:
                self.logger.error(f"❌ Failed to start inotify monitoring: {e}")
                self.inotify_enabled = False
        if not self.inotify_enabled:
            self.logger.info("📁 Linux file monitoring started with polling")
    
    async def stop(self):
        """Stop Linux file monitoring"""
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=5)
                self.logger.info("🛑 inotify monitoring stopped")
        except Exception as e:
            self.logger.error(f"❌ Error stopping inotify: {e}")
        
        # Cancel và await các task async
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        
        await super().stop()
    
    async def _collect_data(self):
        """Collect Linux file system events"""
        try:
            start_time = time.time()
            events = []
            
            # Scan directories for changes (complement to inotify)
            for monitor_path in self.monitor_paths[:5]:  # Limit to 5 paths per scan
                if os.path.exists(monitor_path):
                    try:
                        path_events = await self._scan_directory_for_changes(monitor_path)
                        events.extend(path_events)
                        self.stats['scan_events'] += len(path_events)
                    except Exception as e:
                        self.logger.debug(f"Error scanning {monitor_path}: {e}")
                        continue
            
            # Create summary event periodically
            if self.stats['total_file_events'] % 20 == 0:
                summary_event = await self._create_file_system_summary_event()
                if summary_event:
                    events.append(summary_event)
            
            self.stats['total_file_events'] += len(events)
            
            # Log performance
            collection_time = (time.time() - start_time) * 1000
            if collection_time > 3000:  # 3 seconds
                self.logger.warning(f"⚠️ Slow file collection: {collection_time:.1f}ms")
            elif events:
                self.logger.info(f"🐧 Generated {len(events)} file events ({collection_time:.1f}ms)")
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ File collection failed: {e}")
            return []
    
    async def _handle_file_event(self, action: str, file_path: str, old_path: str = ""):
        """Handle file system event from inotify - FIXED VERSION"""
        try:
            # ✅ FIXED: Rate limiting to prevent spam
            current_time = time.time()
            if hasattr(self, '_last_event_time') and current_time - self._last_event_time < 0.1:
                # Skip events that are too frequent (less than 100ms apart)
                return
            
            self._last_event_time = current_time
            
            # FIXED: Validate agent_id is available
            if not self.agent_id:
                self.logger.error(f"❌ CRITICAL: File event cannot be processed - agent_id is None")
                return
            
            # Check for event deduplication
            event_key = f"{action}:{file_path}"
            
            if event_key in self.recent_file_events:
                if current_time - self.recent_file_events[event_key] < 1.0:  # 1 second dedup
                    return
            
            self.recent_file_events[event_key] = current_time
            
            # Create event with proper validation
            event = await self._create_file_event(action, file_path, old_path)
            if event and event.agent_id:  # FIXED: Validate event has agent_id
                # Tạo task gửi event và lưu vào self._tasks
                send_task = asyncio.create_task(self._send_event_immediately(event))
                self._tasks.append(send_task)
                self.stats['inotify_events'] += 1
                
                # Update stats by action
                if action == 'created':
                    self.stats['file_creation_events'] += 1
                elif action == 'modified':
                    self.stats['file_modification_events'] += 1
                elif action == 'deleted':
                    self.stats['file_deletion_events'] += 1
                elif action == 'moved':
                    self.stats['file_move_events'] += 1
            else:
                self.logger.error(f"❌ Failed to create valid file event for {action}:{file_path}")
                    
        except Exception as e:
            self.logger.error(f"❌ File event handling failed: {e}")
    
    async def _scan_directory_for_changes(self, directory: str, max_depth: int = 2) -> List[EventData]:
        """Scan directory for file changes (polling method)"""
        events = []
        file_count = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                # Limit directory depth
                current_depth = root[len(directory):].count(os.sep)
                if current_depth > max_depth:
                    continue
                
                # Filter directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d not in ['proc', 'sys', 'dev', '__pycache__']]
                
                for filename in files:
                    if file_count >= self.max_files_per_scan:
                        break
                    
                    try:
                        file_path = os.path.join(root, filename)
                        
                        # Skip if should be ignored
                        if self._should_skip_file(file_path):
                            continue
                        
                        # Get file information
                        file_info = self._get_linux_file_info(file_path)
                        if not file_info:
                            continue
                        
                        file_key = file_path
                        
                        # Check if file is new or modified
                        if file_key not in self.monitored_files:
                            # New file
                            event = await self._create_file_event('created', file_path)
                            if event and event.agent_id:  # FIXED: Validate agent_id
                                events.append(event)
                                self.stats['file_creation_events'] += 1
                        else:
                            # Check if modified
                            old_mtime = self.monitored_files[file_key].get('mtime', 0)
                            new_mtime = file_info.get('mtime', 0)
                            
                            if new_mtime > old_mtime:
                                event = await self._create_file_event('modified', file_path)
                                if event and event.agent_id:  # FIXED: Validate agent_id
                                    events.append(event)
                                    self.stats['file_modification_events'] += 1
                        
                        # Update tracking
                        self.monitored_files[file_key] = file_info
                        file_count += 1
                        
                    except (OSError, PermissionError):
                        continue
                    except Exception as e:
                        self.logger.debug(f"Error processing file {filename}: {e}")
                        continue
                
                if file_count >= self.max_files_per_scan:
                    break
            
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
        
        return events
    
    def _get_linux_file_info(self, file_path: str) -> Optional[Dict]:
        """Get Linux-specific file information"""
        try:
            stat_info = os.stat(file_path)
            file_info = {
                'size': stat_info.st_size,
                'mtime': stat_info.st_mtime,
                'atime': stat_info.st_atime,
                'ctime': stat_info.st_ctime,
                'mode': stat.filemode(stat_info.st_mode),
                'uid': stat_info.st_uid,
                'gid': stat_info.st_gid,
                'inode': stat_info.st_ino,
                'device': stat_info.st_dev,
                'links': stat_info.st_nlink
            }
            
            # Get user and group names
            try:
                file_info['owner'] = self.get_linux_user_info(stat_info.st_uid)['username']
                file_info['group'] = self.get_linux_group_info(stat_info.st_gid)['groupname']
            except:
                file_info['owner'] = str(stat_info.st_uid)
                file_info['group'] = str(stat_info.st_gid)
            
            # Check if executable
            file_info['is_executable'] = os.access(file_path, os.X_OK)
            
            # Get file type
            if stat.S_ISREG(stat_info.st_mode):
                file_info['file_type'] = 'regular'
            elif stat.S_ISDIR(stat_info.st_mode):
                file_info['file_type'] = 'directory'
            elif stat.S_ISLNK(stat_info.st_mode):
                file_info['file_type'] = 'symlink'
            elif stat.S_ISFIFO(stat_info.st_mode):
                file_info['file_type'] = 'fifo'
            elif stat.S_ISSOCK(stat_info.st_mode):
                file_info['file_type'] = 'socket'
            elif stat.S_ISBLK(stat_info.st_mode):
                file_info['file_type'] = 'block_device'
            elif stat.S_ISCHR(stat_info.st_mode):
                file_info['file_type'] = 'char_device'
            else:
                file_info['file_type'] = 'unknown'
            
            return file_info
            
        except (OSError, PermissionError):
            return None
        except Exception as e:
            self.logger.debug(f"Error getting file info for {file_path}: {e}")
            return None
    
    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be skipped"""
        try:
            # Skip temporary and cache files
            skip_patterns = [
                '.tmp', '.temp', '.cache', '.log', '.swp', '.bak',
                '__pycache__', '.git/', '.svn/', '.DS_Store'
            ]
            
            file_lower = file_path.lower()
            if any(pattern in file_lower for pattern in skip_patterns):
                return True
            
            # Skip files in /proc, /sys, /dev
            if any(file_path.startswith(proc_path) for proc_path in ['/proc/', '/sys/', '/dev/']):
                return True
            
            # Skip very large files (> 1GB) for performance
            try:
                if os.path.getsize(file_path) > 1024 * 1024 * 1024:
                    return True
            except (OSError, PermissionError):
                return True
            
            # Skip if we can't read the file
            if not os.access(file_path, os.R_OK):
                return True
            
            return False
            
        except Exception:
            return True
    
    def _is_interesting_file(self, file_path: str) -> bool:
        """Check if file is interesting for monitoring"""
        try:
            file_name = os.path.basename(file_path).lower()
            file_ext = Path(file_path).suffix.lower()
            
            # Check interesting extensions
            if file_ext in self.interesting_extensions:
                return True
            
            # Check suspicious patterns
            if any(pattern in file_path.lower() for pattern in self.suspicious_patterns):
                return True
            
            # Check if executable without extension
            if not file_ext and os.access(file_path, os.X_OK):
                return True
            
            # Check configuration files
            if any(conf in file_name for conf in ['config', 'conf', '.rc', 'profile']):
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_suspicious_file(self, file_path: str) -> bool:
        """Check if file is suspicious"""
        try:
            file_lower = file_path.lower()
            
            # Check for system file access
            if any(sys_file in file_lower for sys_file in ['passwd', 'shadow', 'sudoers']):
                return True
            
            # Check for SSH-related files
            if '.ssh/' in file_lower or 'authorized_keys' in file_lower:
                return True
            
            # Check for shell history files
            if any(hist in file_lower for hist in ['.bash_history', '.zsh_history', '.history']):
                return True
            
            # Check for hidden executables
            file_name = os.path.basename(file_path)
            if file_name.startswith('.') and os.access(file_path, os.X_OK):
                return True
            
            return False
            
        except Exception:
            return False
    
    async def _create_file_event(self, action: str, file_path: str, old_path: str = ""):
        """Create file system event with proper agent_id validation - FIXED"""
        try:
            # FIXED: Validate agent_id is available before creating event
            if not self.agent_id:
                self.logger.error(f"❌ CRITICAL: Cannot create file event - agent_id is None")
                return None
            
            action_map = {
                'created': "Create",
                'modified': "Modify",
                'deleted': "Delete",
                'moved': "Modify"
            }
            event_action = action_map.get(action, "Access")
            
            file_info = None
            if action != 'deleted':
                file_info = self._get_linux_file_info(file_path)
            
            severity = self._determine_file_severity(file_path, action, file_info)
            file_name = os.path.basename(file_path) if file_path else "Unknown"
            
            if action == 'moved' and old_path:
                description = f"🐧 LINUX FILE MOVED: {os.path.basename(old_path)} -> {file_name}"
            else:
                description = f"🐧 LINUX FILE {action.upper()}: {file_name}"
            
            # Ensure raw_event_data is a dictionary
            raw_event_data = {
                'platform': 'linux',
                'action': action,
                'is_interesting': self._is_interesting_file(file_path),
                'is_suspicious': self._is_suspicious_file(file_path),
                'monitoring_method': 'inotify' if self.inotify_enabled else 'polling'
            }
            
            if file_info:
                raw_event_data['file_info'] = file_info
            if old_path:
                raw_event_data['old_path'] = old_path
            
            if file_info and file_info.get('size', 0) > self.large_file_threshold:
                self.stats['large_file_events'] += 1
                raw_event_data['large_file'] = True
            
            # FIXED: Create event with validated agent_id
            event_data = EventData(
                event_type="File",
                event_action=event_action,
                event_timestamp=datetime.now(),
                severity=severity,
                agent_id=self.agent_id,  # Ensure agent_id is set
                file_path=file_path,
                file_name=file_name,
                file_size=file_info.get('size', 0) if file_info else 0,
                file_extension=Path(file_path).suffix if file_path else "",
                description=description,
                raw_event_data=raw_event_data
            )
            
            # FIXED: Double-check agent_id is set correctly
            if not event_data.agent_id:
                self.logger.error(f"❌ CRITICAL: Event created without agent_id - File: {file_path}")
                return None
            
            if self._is_suspicious_file(file_path):
                self.stats['suspicious_file_events'] += 1
                event_data.severity = 'High'
                # Update dictionary properly
                if isinstance(event_data.raw_event_data, dict):
                    event_data.raw_event_data['suspicious_reason'] = 'suspicious_file_pattern'
            
            return event_data
            
        except Exception as e:
            self.logger.error(f"❌ File event creation failed: {e}")
            return None

    async def _send_event_immediately(self, event: EventData):
        """✅ REALTIME: Send event immediately to event processor"""
        try:
            self.logger.info(f"🔍 Attempting to send file event immediately: {event.file_name}")
            
            if self.event_processor:
                self.logger.info(f"✅ Event processor found, sending file event: {event.file_name}")
                # Send event directly to event processor for immediate processing
                await self.event_processor.add_event(event)
                self.logger.info(f"✅ File event sent immediately: {event.file_name}")
            else:
                self.logger.error("❌ No event processor available for immediate sending")
                self.logger.error(f"❌ Event processor is: {self.event_processor}")
        except Exception as e:
            self.logger.error(f"❌ Failed to send file event immediately: {e}")
            import traceback
            self.logger.error(f"❌ Traceback: {traceback.format_exc()}")
    
    def _determine_file_severity(self, file_path: str, action: str, file_info: Optional[Dict]) -> str:
        """Determine file event severity"""
        try:
            # Critical for system files
            if any(sys_path in file_path for sys_path in ['/etc/passwd', '/etc/shadow', '/etc/sudoers']):
                return 'Critical'
            # High for suspicious files
            if self._is_suspicious_file(file_path):
                return 'High'
            # High for executable files in user directories
            if '/home/' in file_path and file_info and file_info.get('is_executable'):
                return 'High'
            # Medium for interesting files
            if self._is_interesting_file(file_path):
                return 'Medium'
            # Medium for files in sensitive directories
            sensitive_dirs = ['/etc/', '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/']
            if any(file_path.startswith(sens_dir) for sens_dir in sensitive_dirs):
                return 'Medium'
            # Medium for large files
            if file_info and file_info.get('size', 0) > self.large_file_threshold:
                return 'Medium'
            return 'Info'
        except Exception:
            return 'Info'

    async def _create_file_system_summary_event(self):
        """Create file system summary event"""
        try:
            total_files = len(self.monitored_files)
            return EventData(
                event_type="File",
                event_action="Resource_Usage",
                event_timestamp=datetime.now(),
                severity="Info",
                agent_id=self.agent_id,
                description=f"🐧 LINUX FILE SYSTEM SUMMARY: {total_files} files monitored",
                raw_event_data={
                    'platform': 'linux',
                    'event_subtype': 'file_system_summary',
                    'total_monitored_files': total_files,
                    'file_statistics': self.stats.copy(),
                    'monitoring_paths': self.monitor_paths,
                    'inotify_enabled': self.inotify_enabled,
                    'interesting_extensions': list(self.interesting_extensions),
                    'monitored_path_count': len(self.monitor_paths)
                }
            )
        except Exception as e:
            self.logger.error(f"❌ File system summary event failed: {e}")
            return None

    def get_stats(self) -> Dict:
        """Get detailed Linux file collector statistics"""
        base_stats = super().get_stats()
        base_stats.update({
            'collector_type': 'Linux_File',
            'file_creation_events': self.stats['file_creation_events'],
            'file_modification_events': self.stats['file_modification_events'],
            'file_deletion_events': self.stats['file_deletion_events'],
            'file_move_events': self.stats['file_move_events'],
            'suspicious_file_events': self.stats['suspicious_file_events'],
            'large_file_events': self.stats['large_file_events'],
            'total_file_events': self.stats['total_file_events'],
            'inotify_events': self.stats['inotify_events'],
            'scan_events': self.stats['scan_events'],
            'monitored_files_count': len(self.monitored_files),
            'monitored_paths': self.monitor_paths,
            'inotify_enabled': self.inotify_enabled,
            'watchdog_available': WATCHDOG_AVAILABLE,
            'large_file_threshold_mb': self.large_file_threshold / (1024 * 1024),
            'max_files_per_scan': self.max_files_per_scan,
            'interesting_extensions': list(self.interesting_extensions),
            'linux_file_monitoring': True
        })
        return base_stats