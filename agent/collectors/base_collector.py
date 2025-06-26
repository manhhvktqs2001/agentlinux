# agent/collectors/base_collector.py - Linux Base Collector
"""
Base Collector for Linux EDR Agent - Optimized for Linux systems
Provides common functionality for all Linux data collectors
"""

from abc import ABC, abstractmethod
import asyncio
import logging
import time
import os
import pwd
import grp
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import json

class LinuxBaseCollector(ABC):
    """Abstract base class for Linux data collectors"""
    
    def __init__(self, config_manager, collector_name: str):
        self.config_manager = config_manager
        self.collector_name = collector_name
        self.logger = logging.getLogger(f"collector.{collector_name}")
        
        # Configuration
        self.config = self.config_manager.get_config() if config_manager else {}
        self.collection_config = self.config.get('collection', {})
        
        # Linux-specific configuration
        self.linux_config = self.config.get('linux_settings', {})
        self.proc_path = Path(self.linux_config.get('proc_path', '/proc'))
        self.sys_path = Path(self.linux_config.get('sys_path', '/sys'))
        
        # Collector state
        self.is_running = False
        self.is_initialized = False
        self.start_time: Optional[datetime] = None
        self.is_paused = False
        
        # Linux monitoring settings
        self.immediate_processing = True
        self.polling_interval = 2.0  # Default 2 seconds
        self.max_events_per_interval = 20
        self.real_time_monitoring = True
        
        # Performance tracking
        self.events_collected = 0
        self.events_sent = 0
        self.collection_errors = 0
        self.last_collection_time: Optional[datetime] = None
        self.collection_duration = 0
        self.average_collection_time = 0
        
        # Event processor reference
        self.event_processor = None
        self.agent_id = None
        
        # Linux-specific utilities
        self._collection_times = []
        self._max_collection_history = 50
        self._consecutive_errors = 0
        self._last_error_time = 0
        self._error_backoff = 1
        
        # Linux privilege checking
        self.requires_root = True
        self.has_required_privileges = self._check_privileges()
        
        self.logger.info(f"✅ Linux {collector_name} initialized")
        if not self.has_required_privileges:
            self.logger.warning(f"⚠️ {collector_name} may have limited functionality without root privileges")
    
    def _check_privileges(self) -> bool:
        """Check if we have required privileges for Linux monitoring"""
        try:
            # Check if running as root
            if os.geteuid() == 0:
                return True
            
            # Check if we can read critical files
            test_paths = ['/proc/1/cmdline', '/proc/net/tcp']
            for path in test_paths:
                try:
                    with open(path, 'r') as f:
                        f.read(1)
                except (PermissionError, FileNotFoundError):
                    return False
            
            return True
        except Exception:
            return False
    
    async def initialize(self):
        """Initialize the Linux collector"""
        try:
            self.logger.info(f"🚀 Initializing Linux {self.collector_name}...")
            
            # Validate Linux-specific configuration
            await self._validate_linux_config()
            
            # Check system requirements
            await self._check_system_requirements()
            
            # Perform collector-specific initialization
            await self._collector_specific_init()
            
            self.is_initialized = True
            self.logger.info(f"✅ Linux {self.collector_name} initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} initialization failed: {e}")
            raise Exception(f"Linux collector initialization failed: {e}")
    
    async def start(self):
        """Start the Linux collector"""
        try:
            if not self.is_initialized:
                await self.initialize()
            
            self.is_running = True
            self.start_time = datetime.now()
            
            self.logger.info(f"🚀 Starting Linux collector: {self.collector_name}")
            
            # Start continuous collection loop
            asyncio.create_task(self._linux_collection_loop())
            
            self.logger.info(f"✅ Linux collector started: {self.collector_name}")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} start failed: {e}")
            self.is_running = False
            raise Exception(f"Linux collector start failed: {e}")
    
    async def stop(self):
        """Stop the Linux collector gracefully"""
        try:
            self.logger.info(f"🛑 Stopping Linux {self.collector_name}...")
            self.is_running = False
            
            # Wait for current collection to finish
            max_wait = 5
            wait_count = 0
            while hasattr(self, '_collecting') and self._collecting and wait_count < max_wait:
                await asyncio.sleep(0.1)
                wait_count += 0.1
            
            # Perform collector-specific cleanup
            await self._collector_specific_cleanup()
            
            # Log final statistics
            if self.events_collected > 0:
                uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
                rate = self.events_collected / uptime if uptime > 0 else 0
                self.logger.info(f"📊 {self.collector_name} Final Stats: {self.events_collected} events, {rate:.2f}/sec")
            
            self.logger.info(f"✅ Linux {self.collector_name} stopped")
            
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} stop error: {e}")
    
    async def pause(self):
        """Pause the Linux collector"""
        try:
            if self.is_running and not self.is_paused:
                self.is_paused = True
                self.logger.info(f"⏸️ Linux {self.collector_name} paused")
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} pause error: {e}")
    
    async def resume(self):
        """Resume the Linux collector"""
        try:
            if self.is_running and self.is_paused:
                self.is_paused = False
                self.logger.info(f"▶️ Linux {self.collector_name} resumed")
        except Exception as e:
            self.logger.error(f"❌ {self.collector_name} resume error: {e}")
    
    async def _linux_collection_loop(self):
        """Main collection loop optimized for Linux"""
        self.logger.info(f"🔄 Starting Linux collection loop: {self.collector_name}")
        
        while self.is_running:
            try:
                # Check if collector is paused
                if self.is_paused:
                    await asyncio.sleep(0.5)
                    continue
                
                if hasattr(self, '_collecting') and self._collecting:
                    await asyncio.sleep(0.1)
                    continue
                
                # Check error backoff
                if self._consecutive_errors > 0:
                    if time.time() - self._last_error_time < self._error_backoff:
                        await asyncio.sleep(0.5)
                        continue
                
                collection_start = time.time()
                self._collecting = True
                
                try:
                    # Collect data with timeout
                    result = await asyncio.wait_for(
                        self._collect_data(),
                        timeout=5.0  # 5 second timeout for Linux operations
                    )
                    
                    # Process the result
                    events_processed = 0
                    if isinstance(result, list):
                        for event in result:
                            if hasattr(event, 'event_type'):  # Validate event
                                await self._send_event_immediately(event)
                                events_processed += 1
                    elif hasattr(result, 'event_type'):
                        await self._send_event_immediately(result)
                        events_processed += 1
                    
                    # Update statistics
                    self.last_collection_time = datetime.now()
                    collection_time = time.time() - collection_start
                    self.collection_duration = collection_time
                    
                    # Track collection times
                    self._collection_times.append(collection_time)
                    if len(self._collection_times) > self._max_collection_history:
                        self._collection_times.pop(0)
                    
                    self.average_collection_time = sum(self._collection_times) / len(self._collection_times)
                    
                    # Reset error tracking on success
                    if events_processed > 0:
                        self._consecutive_errors = 0
                        self._error_backoff = 1
                    
                    # Log slow collections
                    if collection_time > 3.0:  # 3 seconds is slow for Linux
                        self.logger.warning(f"⚠️ Slow collection: {collection_time:.1f}s in {self.collector_name}")
                    
                    # Dynamic polling based on activity
                    if events_processed > 0:
                        await asyncio.sleep(self.polling_interval * 0.5)  # Faster when active
                    else:
                        await asyncio.sleep(self.polling_interval)
                    
                except asyncio.TimeoutError:
                    self.logger.warning(f"⚠️ Collection timeout: {self.collector_name}")
                    self.collection_errors += 1
                    self._consecutive_errors += 1
                    self._last_error_time = time.time()
                    self._error_backoff = min(self._error_backoff * 2, 10)
                    await asyncio.sleep(1)
                    
                finally:
                    self._collecting = False
                
            except Exception as e:
                self.logger.error(f"❌ Collection loop error in {self.collector_name}: {e}")
                self.collection_errors += 1
                self._consecutive_errors += 1
                self._last_error_time = time.time()
                self._error_backoff = min(self._error_backoff * 2, 10)
                self._collecting = False
                await asyncio.sleep(2)
    
    async def _send_event_immediately(self, event_data):
        """Send event immediately to event processor - FIXED"""
        try:
            if self.agent_id and not hasattr(event_data, 'agent_id'):
                event_data.agent_id = self.agent_id
            elif self.agent_id and not event_data.agent_id:
                event_data.agent_id = self.agent_id
            if not event_data.agent_id:
                self.logger.error(f"❌ CRITICAL: Event missing agent_id - Type: {event_data.event_type}, Action: {event_data.event_action}")
                self.collection_errors += 1
                return
            # Safely update raw_event_data
            if hasattr(event_data, 'raw_event_data'):
                import json
                if isinstance(event_data.raw_event_data, str):
                    try:
                        raw_data = json.loads(event_data.raw_event_data)
                    except:
                        raw_data = {'original_data': event_data.raw_event_data}
                elif isinstance(event_data.raw_event_data, dict):
                    raw_data = event_data.raw_event_data.copy()
                else:
                    raw_data = {}
                raw_data.update({
                    'platform': 'linux',
                    'collector': self.collector_name,
                    'collection_time': time.time(),
                    'has_root_privileges': self.has_required_privileges,
                    'agent_id_set_by': 'collector'
                })
                # Only serialize if original was a string
                if isinstance(event_data.raw_event_data, str):
                    event_data.raw_event_data = json.dumps(raw_data, default=str)
                else:
                    event_data.raw_event_data = raw_data
            event_type = getattr(event_data, 'event_type', 'Unknown')
            event_action = getattr(event_data, 'event_action', 'Unknown')
            process_name = getattr(event_data, 'process_name', 'Unknown')
            self.logger.info(f"🐧 Linux {event_type} Event: {event_action} - {process_name} (Agent: {event_data.agent_id[:8]}...)")
            if not self.event_processor:
                self.logger.debug("⚠️ Event processor not available")
                self.collection_errors += 1
                return
            await self.event_processor.add_event(event_data)
            self.events_sent += 1
            self.events_collected += 1
            self.logger.debug(f"📤 Linux event sent: {event_type} - {event_action}")
        except Exception as e:
            self.logger.error(f"❌ Event sending failed: {e}")
            self.collection_errors += 1
    
    @abstractmethod
    async def _collect_data(self):
        """Collect data - must be implemented by Linux subclasses"""
        pass
    
    async def _collector_specific_init(self):
        """Collector-specific initialization - override in subclasses"""
        pass
    
    async def _collector_specific_cleanup(self):
        """Collector-specific cleanup - override in subclasses"""
        pass
    
    async def _validate_linux_config(self):
        """Validate Linux-specific configuration"""
        if self.polling_interval < 0.1:
            self.logger.warning("⚠️ Polling interval too low for Linux, setting to 0.1s")
            self.polling_interval = 0.1
        
        if self.max_events_per_interval < 1:
            self.logger.warning("⚠️ Max events per interval too low, setting to 1")
            self.max_events_per_interval = 1
        
        # Check if critical Linux paths exist
        if not self.proc_path.exists():
            raise Exception("Linux /proc filesystem not available")
    
    async def _check_system_requirements(self):
        """Check Linux system requirements"""
        try:
            # Check if we can access /proc
            if not os.access('/proc', os.R_OK):
                self.logger.warning("⚠️ Cannot read /proc filesystem")
            
            # Check if we can access /sys
            if not os.access('/sys', os.R_OK):
                self.logger.warning("⚠️ Cannot read /sys filesystem")
            
            # Check specific collector requirements
            await self._check_collector_requirements()
            
        except Exception as e:
            self.logger.warning(f"⚠️ System requirements check failed: {e}")
    
    async def _check_collector_requirements(self):
        """Check collector-specific requirements - override in subclasses"""
        pass
    
    def set_event_processor(self, event_processor):
        """Set the event processor for this collector"""
        self.event_processor = event_processor
        self.logger.debug(f"Event processor set for {self.collector_name}")
    
    def set_agent_id(self, agent_id: str):
        """Set the agent ID for this collector"""
        self.agent_id = agent_id
        self.logger.debug(f"Agent ID set for {self.collector_name}: {agent_id}")
    
    def get_linux_user_info(self, uid: int) -> Dict[str, str]:
        """Get Linux user information by UID"""
        try:
            user_info = pwd.getpwuid(uid)
            return {
                'username': user_info.pw_name,
                'uid': str(uid),
                'gid': str(user_info.pw_gid),
                'home_dir': user_info.pw_dir,
                'shell': user_info.pw_shell
            }
        except KeyError:
            return {
                'username': f'uid_{uid}',
                'uid': str(uid),
                'gid': 'unknown',
                'home_dir': 'unknown',
                'shell': 'unknown'
            }
    
    def get_linux_group_info(self, gid: int) -> Dict[str, str]:
        """Get Linux group information by GID"""
        try:
            group_info = grp.getgrgid(gid)
            return {
                'groupname': group_info.gr_name,
                'gid': str(gid),
                'members': group_info.gr_mem
            }
        except KeyError:
            return {
                'groupname': f'gid_{gid}',
                'gid': str(gid),
                'members': []
            }
    
    def read_proc_file(self, path: str) -> Optional[str]:
        """Safely read a file from /proc"""
        try:
            with open(path, 'r') as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            return None
    
    def parse_proc_status(self, pid: int) -> Dict[str, str]:
        """Parse /proc/PID/status file"""
        try:
            status = {}
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        status[key.strip()] = value.strip()
            return status
        except:
            return {}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get Linux collector statistics"""
        uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            'collector_name': self.collector_name,
            'platform': 'linux',
            'is_running': self.is_running,
            'is_initialized': self.is_initialized,
            'is_paused': self.is_paused,
            'uptime_seconds': uptime,
            'events_collected': self.events_collected,
            'events_sent': self.events_sent,
            'collection_errors': self.collection_errors,
            'consecutive_errors': self._consecutive_errors,
            'last_collection_time': self.last_collection_time.isoformat() if self.last_collection_time else None,
            'polling_interval': self.polling_interval,
            'real_time_monitoring': self.real_time_monitoring,
            'events_per_minute': (self.events_collected / max(uptime / 60, 1)) if uptime > 0 else 0,
            'collection_duration_ms': self.collection_duration * 1000,
            'average_collection_time_ms': self.average_collection_time * 1000,
            'error_backoff_seconds': self._error_backoff,
            'has_root_privileges': self.has_required_privileges,
            'proc_path_accessible': self.proc_path.exists(),
            'sys_path_accessible': self.sys_path.exists()
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform Linux collector health check"""
        try:
            health_status = {
                'healthy': True,
                'collector_name': self.collector_name,
                'platform': 'linux',
                'is_running': self.is_running,
                'is_initialized': self.is_initialized,
                'issues': []
            }
            
            # Check if collector is running properly
            if self.is_initialized and not self.is_running:
                health_status['healthy'] = False
                health_status['issues'].append('Collector is not running')
            
            # Check error rate
            uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            error_rate = self.collection_errors / max(uptime / 60, 1) if uptime > 60 else 0
            
            if error_rate > 2.0:  # More than 2 errors per minute
                health_status['healthy'] = False
                health_status['issues'].append(f'High error rate: {error_rate:.1f} errors/min')
            
            # Check consecutive errors
            if self._consecutive_errors > 10:
                health_status['healthy'] = False
                health_status['issues'].append(f'Too many consecutive errors: {self._consecutive_errors}')
            
            # Check if collection is stalled
            if (self.last_collection_time and 
                (datetime.now() - self.last_collection_time).total_seconds() > 60):
                health_status['healthy'] = False
                health_status['issues'].append('Collection appears to be stalled')
            
            # Check Linux-specific issues
            if not self.has_required_privileges:
                health_status['issues'].append('Limited privileges may affect monitoring')
            
            if not self.proc_path.exists():
                health_status['healthy'] = False
                health_status['issues'].append('/proc filesystem not accessible')
            
            return health_status
            
        except Exception as e:
            self.logger.error(f"❌ Health check failed: {e}")
            return {
                'healthy': False,
                'collector_name': self.collector_name,
                'platform': 'linux',
                'issues': [f'Health check failed: {str(e)}']
            }

# Alias for backward compatibility
BaseCollector = LinuxBaseCollector