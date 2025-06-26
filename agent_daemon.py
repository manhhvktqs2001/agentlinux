#!/usr/bin/env python3
"""
Linux EDR Agent - Daemon Mode
Background service mode for SystemD integration
"""

import asyncio
import logging
import signal
import sys
import os
import time
import atexit
from pathlib import Path
from datetime import datetime

# Check root privileges
if os.geteuid() != 0:
    print("ERROR: Linux EDR Agent daemon requires root privileges")
    sys.exit(1)

def setup_imports():
    """Setup import paths for Linux agent daemon"""
    try:
        current_dir = Path(__file__).parent.absolute()
        if str(current_dir) not in sys.path:
            sys.path.insert(0, str(current_dir))
        
        agent_dir = current_dir / 'agent'
        if str(agent_dir) not in sys.path:
            sys.path.insert(0, str(agent_dir))
        
        return True
    except Exception as e:
        print(f"Failed to setup imports: {e}")
        return False

def setup_daemon_logging():
    """Setup logging for daemon mode"""
    try:
        # Create log directory
        log_dir = Path('/var/log/edr-agent')
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'edr-agent.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        # Set specific log levels
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('asyncio').setLevel(logging.WARNING)
        
        return True
    except Exception as e:
        print(f"Failed to setup logging: {e}")
        return False

class LinuxEDRDaemon:
    """Linux EDR Agent Daemon for SystemD service"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.agent_manager = None
        self.config_manager = None
        self.is_running = False
        self.start_time = None
        
        # Daemon-specific settings
        self.pidfile = Path('/var/run/edr-agent.pid')
        self.working_dir = Path('/opt/edr-agent')
        
        # Performance tracking
        self.performance_stats = {
            'daemon_start_time': None,
            'events_processed': 0,
            'uptime_seconds': 0
        }
    
    def write_pidfile(self):
        """Write process ID to pidfile"""
        try:
            with open(self.pidfile, 'w') as f:
                f.write(str(os.getpid()))
            self.logger.info(f"PID file written: {self.pidfile}")
        except Exception as e:
            self.logger.error(f"Failed to write PID file: {e}")
    
    def remove_pidfile(self):
        """Remove pidfile on exit"""
        try:
            if self.pidfile.exists():
                self.pidfile.unlink()
                self.logger.info(f"PID file removed: {self.pidfile}")
        except Exception as e:
            self.logger.error(f"Failed to remove PID file: {e}")
    
    async def initialize(self):
        """Initialize the daemon"""
        try:
            self.logger.info("🐧 Initializing Linux EDR Agent Daemon...")
            
            # Import required modules
            from agent.core.config_manager import ConfigManager
            from agent.core.agent_manager import LinuxAgentManager
            
            # Setup configuration
            self.logger.info("📋 Loading daemon configuration...")
            self.config_manager = ConfigManager()
            await self.config_manager.load_config()
            
            # Initialize agent manager
            self.logger.info("🎯 Creating Linux agent manager for daemon...")
            self.agent_manager = LinuxAgentManager(self.config_manager)
            await self.agent_manager.initialize()
            
            self.logger.info("✅ Linux EDR Agent Daemon initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Daemon initialization failed: {e}")
            raise
    
    async def start(self):
        """Start the daemon"""
        try:
            self.logger.info("🚀 Starting Linux EDR Agent Daemon...")
            
            # Write PID file
            self.write_pidfile()
            
            # Register cleanup
            atexit.register(self.remove_pidfile)
            
            # Start the agent
            await self.agent_manager.start()
            
            # Set running state
            self.is_running = True
            self.start_time = time.time()
            self.performance_stats['daemon_start_time'] = self.start_time
            
            self.logger.info("✅ Linux EDR Agent Daemon started successfully")
            self.logger.info(f"📋 PID: {os.getpid()}")
            self.logger.info(f"📁 Working Directory: {os.getcwd()}")
            self.logger.info(f"📝 Log Directory: /var/log/edr-agent/")
            
            # Start daemon monitoring tasks
            asyncio.create_task(self._daemon_monitoring_loop())
            asyncio.create_task(self._daemon_stats_loop())
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start daemon: {e}")
            raise
    
    async def stop(self):
        """Stop the daemon gracefully"""
        try:
            self.logger.info("🛑 Stopping Linux EDR Agent Daemon...")
            
            # Set running state
            self.is_running = False
            
            # Stop agent manager
            if self.agent_manager:
                await self.agent_manager.stop()
            
            # Calculate final stats
            if self.start_time:
                uptime = time.time() - self.start_time
                self.performance_stats['uptime_seconds'] = uptime
                self.logger.info(f"📊 Daemon uptime: {uptime:.1f} seconds ({uptime/3600:.2f} hours)")
            
            # Remove PID file
            self.remove_pidfile()
            
            self.logger.info("✅ Linux EDR Agent Daemon stopped successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping daemon: {e}")
    
    async def _daemon_monitoring_loop(self):
        """Daemon monitoring loop"""
        try:
            while self.is_running:
                try:
                    # Monitor daemon health
                    if self.agent_manager:
                        # Check if agent is still responsive
                        if hasattr(self.agent_manager, 'is_monitoring'):
                            if not self.agent_manager.is_monitoring:
                                self.logger.warning("⚠️ Agent monitoring appears to be stopped")
                    
                    # Check system resources
                    try:
                        import psutil
                        current_process = psutil.Process()
                        cpu_percent = current_process.cpu_percent()
                        memory_info = current_process.memory_info()
                        
                        # Log if resource usage is high
                        if cpu_percent > 20:  # 20% CPU
                            self.logger.warning(f"⚠️ High CPU usage: {cpu_percent:.1f}%")
                        
                        if memory_info.rss > 512 * 1024 * 1024:  # 512MB
                            memory_mb = memory_info.rss / 1024 / 1024
                            self.logger.warning(f"⚠️ High memory usage: {memory_mb:.1f}MB")
                    
                    except ImportError:
                        pass
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Daemon monitoring error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ Daemon monitoring loop failed: {e}")
    
    async def _daemon_stats_loop(self):
        """Daemon statistics logging loop"""
        try:
            while self.is_running:
                try:
                    # Log daemon statistics every 10 minutes
                    if int(time.time()) % 600 == 0:  # Every 10 minutes
                        uptime = time.time() - self.start_time if self.start_time else 0
                        
                        self.logger.info("📊 Daemon Statistics:")
                        self.logger.info(f"   🕒 Uptime: {uptime:.1f} seconds ({uptime/3600:.2f} hours)")
                        self.logger.info(f"   📋 PID: {os.getpid()}")
                        self.logger.info(f"   🐧 Platform: Linux")
                        
                        if self.agent_manager and hasattr(self.agent_manager, 'get_status'):
                            status = self.agent_manager.get_status()
                            self.logger.info(f"   🎯 Agent Status: {status.get('is_monitoring', 'Unknown')}")
                            self.logger.info(f"   📊 Collectors: {len(status.get('collectors', []))}")
                        
                        self.logger.info("-" * 40)
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Daemon stats error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ Daemon stats loop failed: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle system signals"""
        self.logger.info(f"🛑 Received signal {signum}")
        
        if signum in [signal.SIGTERM, signal.SIGINT]:
            self.logger.info("🛑 Graceful shutdown requested")
            asyncio.create_task(self.stop())
        elif signum == signal.SIGHUP:
            self.logger.info("🔄 Reload signal received")
            # Could implement configuration reload here
        elif signum == signal.SIGUSR1:
            self.logger.info("📊 Status signal received")
            # Could implement status reporting here

async def run_daemon():
    """Run the daemon main loop"""
    # Setup logging
    if not setup_daemon_logging():
        print("Failed to setup logging")
        sys.exit(1)
    
    logger = logging.getLogger(__name__)
    logger.info("🐧 Linux EDR Agent Daemon starting...")
    
    # Create daemon instance
    daemon = LinuxEDRDaemon()
    
    # Setup signal handlers
    signal.signal(signal.SIGTERM, daemon.signal_handler)
    signal.signal(signal.SIGINT, daemon.signal_handler)
    signal.signal(signal.SIGHUP, daemon.signal_handler)
    signal.signal(signal.SIGUSR1, daemon.signal_handler)
    
    try:
        # Initialize daemon
        await daemon.initialize()
        
        # Start daemon
        await daemon.start()
        
        # Main daemon loop
        while daemon.is_running:
            try:
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"❌ Daemon loop error: {e}")
                await asyncio.sleep(5)
        
    except Exception as e:
        logger.error(f"❌ Daemon error: {e}", exc_info=True)
    finally:
        await daemon.stop()

def main():
    """Main entry point for daemon"""
    try:
        # Setup imports
        if not setup_imports():
            print("Failed to setup imports")
            sys.exit(1)
        
        # Run daemon
        asyncio.run(run_daemon())
        
    except KeyboardInterrupt:
        print("Daemon stopped by signal")
    except Exception as e:
        print(f"Daemon error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()