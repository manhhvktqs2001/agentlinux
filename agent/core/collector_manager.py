# agent/core/collector_manager.py - FIXED Linux Collector Manager
"""
Linux Collector Manager - FIXED VERSION
Manages data collectors for Linux EDR agent
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

from agent.core.config_manager import ConfigManager
from agent.core.event_processor import EventProcessor

class LinuxCollectorManager:
    """
    Linux Collector Manager - FIXED VERSION
    Manages all data collectors for the Linux EDR agent
    """
    
    def __init__(self, config_manager: ConfigManager, event_processor: EventProcessor):
        self.config_manager = config_manager
        self.event_processor = event_processor
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.config = self.config_manager.get_config()
        self.collection_config = self.config.get('collection', {})
        
        # State
        self.is_running = False
        self.is_initialized = False
        self.agent_id: Optional[str] = None
        
        # Collectors
        self.collectors = {}
        self.collector_tasks = {}
        
        # Statistics
        self.total_events_collected = 0
        self.collectors_healthy = 0
        self.start_time = None
        
        self.logger.info("📊 Linux Collector Manager initialized")
    
    def set_agent_id(self, agent_id: str):
        """Set agent ID for all collectors"""
        self.agent_id = agent_id
        self.logger.info(f"Agent ID set for collector manager: {agent_id}")
        
        # Update existing collectors
        for collector in self.collectors.values():
            if hasattr(collector, 'set_agent_id'):
                collector.set_agent_id(agent_id)
    
    async def initialize(self):
        """Initialize collector manager and all collectors"""
        try:
            self.logger.info("🚀 Initializing Linux Collector Manager...")
            
            # Import collectors
            await self._import_collectors()
            
            # Initialize enabled collectors
            await self._initialize_enabled_collectors()
            
            self.is_initialized = True
            self.logger.info(f"✅ Collector Manager initialized with {len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Collector Manager initialization failed: {e}")
            raise
    
    async def _import_collectors(self):
        """Import available collector classes"""
        try:
            # Import collector classes
            from agent.collectors.process_collector import LinuxProcessCollector
            from agent.collectors.file_collector import LinuxFileCollector
            from agent.collectors.network_collector import LinuxNetworkCollector
            from agent.collectors.authentication_collector import LinuxAuthenticationCollector
            from agent.collectors.system_collector import LinuxSystemCollector
            
            # Store available collectors
            self.available_collectors = {
                'process': LinuxProcessCollector,
                'file': LinuxFileCollector,
                'network': LinuxNetworkCollector,
                'authentication': LinuxAuthenticationCollector,
                'system': LinuxSystemCollector
            }
            
            self.logger.info(f"📦 Imported {len(self.available_collectors)} collector types")
            
        except Exception as e:
            self.logger.error(f"❌ Error importing collectors: {e}")
            raise
    
    async def _initialize_enabled_collectors(self):
        """Initialize only enabled collectors"""
        try:
            # Determine which collectors to enable
            collectors_to_enable = {}
            
            if self.collection_config.get('collect_processes', True):
                collectors_to_enable['process'] = self.available_collectors['process']
            
            if self.collection_config.get('collect_files', True):
                collectors_to_enable['file'] = self.available_collectors['file']
            
            if self.collection_config.get('collect_network', True):
                collectors_to_enable['network'] = self.available_collectors['network']
            
            if self.collection_config.get('collect_authentication', True):
                collectors_to_enable['authentication'] = self.available_collectors['authentication']
            
            if self.collection_config.get('collect_system_events', True):
                collectors_to_enable['system'] = self.available_collectors['system']
            
            # Initialize each enabled collector
            for collector_name, collector_class in collectors_to_enable.items():
                try:
                    self.logger.info(f"📊 Initializing {collector_name} collector...")
                    
                    # Create collector instance
                    collector = collector_class(self.config_manager)
                    
                    # Set event processor
                    if hasattr(collector, 'set_event_processor'):
                        collector.set_event_processor(self.event_processor)
                    
                    # Set agent ID if available
                    if self.agent_id and hasattr(collector, 'set_agent_id'):
                        collector.set_agent_id(self.agent_id)
                    
                    # Initialize collector
                    await collector.initialize()
                    
                    # Store collector
                    self.collectors[collector_name] = collector
                    
                    self.logger.info(f"✅ {collector_name} collector initialized")
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to initialize {collector_name} collector: {e}")
                    # Continue with other collectors
            
            self.logger.info(f"✅ Initialized {len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Error initializing collectors: {e}")
            raise
    
    async def start(self):
        """Start all collectors"""
        try:
            self.logger.info("🚀 Starting Linux Collector Manager...")
            
            self.is_running = True
            self.start_time = datetime.now()
            
            # Start each collector
            for collector_name, collector in self.collectors.items():
                try:
                    self.logger.info(f"📊 Starting {collector_name} collector...")
                    
                    # Start collector
                    await collector.start()
                    
                    # Create monitoring task for this collector
                    task = asyncio.create_task(
                        self._collector_monitoring_loop(collector_name, collector)
                    )
                    self.collector_tasks[collector_name] = task
                    
                    self.logger.info(f"✅ {collector_name} collector started")
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to start {collector_name} collector: {e}")
            
            # Start manager monitoring
            asyncio.create_task(self._manager_monitoring_loop())
            
            self.logger.info(f"✅ Collector Manager started with {len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Collector Manager start failed: {e}")
            raise
    
    async def stop(self):
        """Stop all collectors gracefully"""
        try:
            self.logger.info("🛑 Stopping Linux Collector Manager...")
            
            self.is_running = False
            
            # Cancel monitoring tasks
            for task_name, task in self.collector_tasks.items():
                try:
                    if not task.done():
                        task.cancel()
                    self.logger.info(f"✅ {task_name} monitoring task cancelled")
                except Exception as e:
                    self.logger.error(f"❌ Error cancelling {task_name} task: {e}")
            
            # Wait for tasks to complete
            if self.collector_tasks:
                await asyncio.gather(*self.collector_tasks.values(), return_exceptions=True)
            
            # Stop each collector
            for collector_name, collector in self.collectors.items():
                try:
                    self.logger.info(f"📊 Stopping {collector_name} collector...")
                    
                    if hasattr(collector, 'stop'):
                        await collector.stop()
                    
                    self.logger.info(f"✅ {collector_name} collector stopped")
                    
                except Exception as e:
                    self.logger.error(f"❌ Error stopping {collector_name} collector: {e}")
            
            self.logger.info("✅ Collector Manager stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping Collector Manager: {e}")
    
    async def _collector_monitoring_loop(self, collector_name: str, collector):
        """Monitor individual collector health"""
        try:
            while self.is_running:
                try:
                    # Check collector health
                    if hasattr(collector, 'is_running'):
                        if not collector.is_running:
                            self.logger.warning(f"⚠️ {collector_name} collector is not running")
                    
                    # Get collector statistics
                    if hasattr(collector, 'get_stats'):
                        stats = collector.get_stats()
                        if stats.get('events_collected', 0) > 0:
                            self.total_events_collected += stats.get('events_collected', 0)
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ {collector_name} monitoring error: {e}")
                    await asyncio.sleep(60)
                    
        except asyncio.CancelledError:
            self.logger.info(f"🛑 {collector_name} monitoring cancelled")
        except Exception as e:
            self.logger.error(f"❌ {collector_name} monitoring failed: {e}")
    
    async def _manager_monitoring_loop(self):
        """Monitor overall collector manager health"""
        try:
            while self.is_running:
                try:
                    # Update health status
                    self._update_health_status()
                    
                    # Log status every 5 minutes
                    if int(time.time()) % 300 == 0:
                        self._log_status()
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"❌ Manager monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except asyncio.CancelledError:
            self.logger.info("🛑 Manager monitoring cancelled")
        except Exception as e:
            self.logger.error(f"❌ Manager monitoring failed: {e}")
    
    def _update_health_status(self):
        """Update collector health status"""
        try:
            healthy_count = 0
            
            for collector_name, collector in self.collectors.items():
                if hasattr(collector, 'is_running') and collector.is_running:
                    healthy_count += 1
            
            self.collectors_healthy = healthy_count
            
        except Exception as e:
            self.logger.debug(f"Error updating health status: {e}")
    
    def _log_status(self):
        """Log collector manager status"""
        try:
            uptime = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
            
            self.logger.info("📊 Collector Manager Status:")
            self.logger.info(f"   ⏱️ Uptime: {uptime:.1f} seconds")
            self.logger.info(f"   📊 Total Collectors: {len(self.collectors)}")
            self.logger.info(f"   ✅ Healthy Collectors: {self.collectors_healthy}")
            self.logger.info(f"   📥 Total Events: {self.total_events_collected}")
            self.logger.info(f"   🐧 Platform: Linux")
            
        except Exception as e:
            self.logger.debug(f"Error logging status: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get collector manager status"""
        try:
            collector_status = {}
            
            for collector_name, collector in self.collectors.items():
                try:
                    if hasattr(collector, 'get_stats'):
                        collector_status[collector_name] = collector.get_stats()
                    else:
                        collector_status[collector_name] = {
                            'is_running': getattr(collector, 'is_running', False)
                        }
                except Exception as e:
                    collector_status[collector_name] = {'error': str(e)}
            
            return {
                'manager_type': 'linux_collector_manager',
                'is_running': self.is_running,
                'is_initialized': self.is_initialized,
                'total_collectors': len(self.collectors),
                'healthy_collectors': self.collectors_healthy,
                'total_events_collected': self.total_events_collected,
                'collector_names': list(self.collectors.keys()),
                'collector_status': collector_status,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'agent_id': self.agent_id
            }
            
        except Exception as e:
            return {
                'manager_type': 'linux_collector_manager',
                'error': str(e),
                'is_running': self.is_running
            }
    
    async def pause_collector(self, collector_name: str):
        """Pause specific collector"""
        try:
            if collector_name in self.collectors:
                collector = self.collectors[collector_name]
                if hasattr(collector, 'pause'):
                    await collector.pause()
                    self.logger.info(f"⏸️ {collector_name} collector paused")
                else:
                    self.logger.warning(f"⚠️ {collector_name} collector does not support pause")
            else:
                self.logger.error(f"❌ Collector {collector_name} not found")
        except Exception as e:
            self.logger.error(f"❌ Error pausing {collector_name} collector: {e}")
    
    async def resume_collector(self, collector_name: str):
        """Resume specific collector"""
        try:
            if collector_name in self.collectors:
                collector = self.collectors[collector_name]
                if hasattr(collector, 'resume'):
                    await collector.resume()
                    self.logger.info(f"▶️ {collector_name} collector resumed")
                else:
                    self.logger.warning(f"⚠️ {collector_name} collector does not support resume")
            else:
                self.logger.error(f"❌ Collector {collector_name} not found")
        except Exception as e:
            self.logger.error(f"❌ Error resuming {collector_name} collector: {e}")
    
    async def restart_collector(self, collector_name: str):
        """Restart specific collector"""
        try:
            if collector_name in self.collectors:
                collector = self.collectors[collector_name]
                
                self.logger.info(f"🔄 Restarting {collector_name} collector...")
                
                # Stop collector
                if hasattr(collector, 'stop'):
                    await collector.stop()
                
                # Start collector again
                if hasattr(collector, 'start'):
                    await collector.start()
                
                self.logger.info(f"✅ {collector_name} collector restarted")
            else:
                self.logger.error(f"❌ Collector {collector_name} not found")
        except Exception as e:
            self.logger.error(f"❌ Error restarting {collector_name} collector: {e}")
    
    def get_collector_health(self) -> Dict[str, bool]:
        """Get health status of all collectors"""
        health_status = {}
        
        try:
            for collector_name, collector in self.collectors.items():
                if hasattr(collector, 'is_running'):
                    health_status[collector_name] = collector.is_running
                else:
                    health_status[collector_name] = False
        except Exception as e:
            self.logger.error(f"❌ Error getting collector health: {e}")
        
        return health_status

# Backward compatibility alias
ParallelCollectorManager = LinuxCollectorManager