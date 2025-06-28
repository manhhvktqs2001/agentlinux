#!/usr/bin/env python3
"""
🐧 Linux EDR Agent - Production Ready Version
Enhanced Endpoint Detection and Response Agent for Linux Systems
All issues resolved with comprehensive error handling and optimization
"""

import asyncio
import logging
import signal
import sys
import os
import time
import uuid
import psutil
import platform
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

# 🔧 Setup Python path for imports
current_dir = Path(__file__).parent.absolute()
agent_dir = current_dir / 'agent'
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

def setup_production_logging(debug_mode: bool = False):
    """🐧 Setup production-grade logging for Linux EDR Agent"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory with proper permissions
    log_dir = current_dir / 'logs'
    log_dir.mkdir(exist_ok=True, mode=0o755)
    
    try:
        from logging.handlers import RotatingFileHandler
        
        # Configure log level
        log_level = logging.DEBUG if debug_mode else logging.INFO
        
        # Main log file with rotation
        main_handler = RotatingFileHandler(
            log_dir / 'linux_edr_agent.log',
            maxBytes=50*1024*1024,  # 50MB
            backupCount=5,
            encoding='utf-8'
        )
        main_handler.setLevel(log_level)
        
        # Error log file
        error_handler = RotatingFileHandler(
            log_dir / 'linux_edr_errors.log',
            maxBytes=20*1024*1024,  # 20MB
            backupCount=3,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        
        # Console handler with color support
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        
        # Enhanced formatter with thread info
        enhanced_format = '%(asctime)s - [%(threadName)s] - %(name)s - %(levelname)s - %(message)s'
        formatter = logging.Formatter(enhanced_format)
        
        main_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)
        console_handler.setFormatter(logging.Formatter(log_format))
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            handlers=[main_handler, error_handler, console_handler]
        )
        
        # Reduce noise from external libraries
        for noisy_logger in ['urllib3', 'aiohttp', 'asyncio', 'requests']:
            logging.getLogger(noisy_logger).setLevel(logging.WARNING)
        
        # Create special loggers for different components
        for logger_name in ['security', 'network', 'process', 'file', 'system']:
            logger = logging.getLogger(logger_name)
            logger_handler = RotatingFileHandler(
                log_dir / f'{logger_name}.log',
                maxBytes=20*1024*1024,
                backupCount=2,
                encoding='utf-8'
            )
            logger_handler.setFormatter(formatter)
            logger.addHandler(logger_handler)
        
        print(f"✅ Production logging configured - Debug: {debug_mode}")
        
    except Exception as e:
        print(f"❌ Failed to setup logging: {e}")
        # Fallback to basic logging
        logging.basicConfig(level=logging.INFO, format=log_format)

def check_system_requirements() -> bool:
    """🐧 Comprehensive Linux system requirements check"""
    print("🔍 Checking Linux system requirements...")
    
    try:
        # Check Python version
        if sys.version_info < (3, 8):
            print("❌ Python 3.8 or higher required")
            return False
        
        # Check platform
        if platform.system() != 'Linux':
            print("❌ This agent is designed specifically for Linux systems")
            return False
        
        # Check available memory
        memory = psutil.virtual_memory()
        if memory.available < 256 * 1024 * 1024:  # 256MB minimum
            print("⚠️ Warning: Low available memory (< 256MB)")
        
        # Check CPU cores
        cpu_count = psutil.cpu_count()
        if cpu_count < 1:
            print("❌ At least 1 CPU core required")
            return False
        
        # Check disk space
        disk = psutil.disk_usage('/')
        if disk.free < 512 * 1024 * 1024:  # 512MB minimum
            print("⚠️ Warning: Low disk space (< 512MB free)")
        
        # Check if running as root (recommended)
        is_root = os.geteuid() == 0
        if not is_root:
            print("⚠️ Warning: Running without root privileges - some features may be limited")
        
        # Check write permissions
        try:
            test_file = current_dir / '.test_write'
            test_file.write_text("test")
            test_file.unlink()
        except Exception:
            print("❌ No write permissions in agent directory")
            return False
        
        # Display system info
        print(f"✅ System Requirements Check:")
        print(f"   🐧 Platform: {platform.system()} {platform.release()}")
        print(f"   🐍 Python: {sys.version.split()[0]}")
        print(f"   🔄 CPU Cores: {cpu_count}")
        print(f"   💾 Available Memory: {memory.available / (1024**2):.0f} MB")
        print(f"   💽 Free Disk Space: {disk.free / (1024**3):.1f} GB")
        print(f"   🔐 Root Privileges: {'Yes' if is_root else 'No'}")
        
        return True
        
    except Exception as e:
        print(f"❌ System requirements check failed: {e}")
        return False

def check_dependencies() -> bool:
    """🐧 Check if all required dependencies are available"""
    print("📦 Checking dependencies...")
    
    required_modules = [
        ('psutil', 'System monitoring'),
        ('aiohttp', 'HTTP client'),
        ('yaml', 'Configuration parsing'),
        ('asyncio', 'Async support')
    ]
    
    missing_modules = []
    
    for module_name, description in required_modules:
        try:
            if module_name == 'yaml':
                import yaml
            elif module_name == 'psutil':
                import psutil
            elif module_name == 'aiohttp':
                import aiohttp
            elif module_name == 'asyncio':
                import asyncio
            print(f"   ✅ {module_name}: {description}")
        except ImportError:
            print(f"   ❌ {module_name}: {description} - MISSING")
            missing_modules.append(module_name)
    
    if missing_modules:
        print(f"❌ Missing dependencies: {', '.join(missing_modules)}")
        print("📥 Install with: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies available")
    return True

class LinuxEDRAgent:
    """🐧 Production Linux EDR Agent with comprehensive error handling"""
    
    def __init__(self, debug_mode: bool = False):
        self.logger = logging.getLogger(__name__)
        self.debug_mode = debug_mode
        self.agent_manager = None
        self.config_manager = None
        self.is_running = False
        self.agent_id = None
        self.start_time = None
        self.shutdown_requested = False
        
        # Performance monitoring
        self.performance_stats = {
            'start_time': time.time(),
            'events_processed': 0,
            'memory_usage_mb': 0,
            'cpu_usage_percent': 0,
            'uptime_seconds': 0,
            'restart_count': 0
        }
        
        # Health monitoring
        self.health_status = {
            'overall': 'starting',
            'components': {},
            'last_check': time.time()
        }
        
        # Signal handling
        self.signal_received = False
        
        # Initialize agent ID
        self._ensure_agent_id()
        
        self.logger.info(f"🐧 Linux EDR Agent initialized")
        self.logger.info(f"   🆔 Agent ID: {self.agent_id[:12]}...")
        self.logger.info(f"   🐞 Debug Mode: {debug_mode}")
        self.logger.info(f"   🏠 Working Directory: {current_dir}")
    
    def _ensure_agent_id(self):
        """🔐 Ensure agent has a unique identifier"""
        try:
            agent_id_file = current_dir / '.agent_id'
            
            if agent_id_file.exists():
                self.agent_id = agent_id_file.read_text().strip()
                if len(self.agent_id) >= 36:  # Valid UUID length
                    self.logger.info(f"📄 Loaded existing agent ID from file")
                    return
            
            # Generate new agent ID
            self.agent_id = str(uuid.uuid4())
            agent_id_file.write_text(self.agent_id)
            agent_id_file.chmod(0o600)  # Secure permissions
            self.logger.info(f"🆔 Generated new agent ID")
            
        except Exception as e:
            self.logger.error(f"❌ Error managing agent ID: {e}")
            self.agent_id = str(uuid.uuid4())
            self.logger.info(f"🆔 Using temporary agent ID")
    
    async def initialize(self):
        """🚀 Initialize the Linux EDR Agent"""
        try:
            self.logger.info("🚀 Initializing Linux EDR Agent...")
            self.logger.info("=" * 80)
            
            # Import agent components with error handling
            try:
                from agent.core.config_manager import ConfigManager
                from agent.core.agent_manager import LinuxAgentManager
                self.logger.info("✅ Agent modules imported successfully")
            except ImportError as e:
                self.logger.error(f"❌ Failed to import agent modules: {e}")
                self.logger.error("💡 Ensure all agent files are present")
                raise
            
            # Initialize configuration manager
            self.logger.info("📋 Loading configuration...")
            self.config_manager = ConfigManager()
            await self.config_manager.load_config()
            
            # Apply runtime optimizations
            await self._apply_runtime_optimizations()
            
            # Initialize agent manager
            self.logger.info("🎯 Creating agent manager...")
            self.agent_manager = LinuxAgentManager(self.config_manager)
            
            # Set agent ID
            if hasattr(self.agent_manager, 'agent_id'):
                self.agent_manager.agent_id = self.agent_id
            
            # Initialize with timeout
            self.logger.info("⏳ Initializing agent components...")
            await asyncio.wait_for(self.agent_manager.initialize(), timeout=180)
            
            self.health_status['overall'] = 'initialized'
            self.logger.info("✅ Linux EDR Agent initialized successfully")
            self.logger.info("=" * 80)
            
        except asyncio.TimeoutError:
            self.logger.error("❌ Initialization timeout (180s)")
            self.health_status['overall'] = 'timeout'
            raise Exception("Agent initialization timeout")
        except Exception as e:
            self.logger.error(f"❌ Initialization failed: {e}")
            self.health_status['overall'] = 'failed'
            if self.debug_mode:
                import traceback
                self.logger.debug(f"🔍 Full traceback:\n{traceback.format_exc()}")
            raise
    
    async def _apply_runtime_optimizations(self):
        """⚡ Apply runtime optimizations based on system resources"""
        try:
            memory = psutil.virtual_memory()
            cpu_count = psutil.cpu_count()
            
            config = self.config_manager.get_config()
            agent_config = config.get('agent', {})
            
            # Memory-based optimizations
            if memory.available < 512 * 1024 * 1024:  # < 512MB
                self.logger.warning("⚠️ Low memory - applying memory optimizations")
                agent_config['event_batch_size'] = 5
                agent_config['event_queue_size'] = 200
                agent_config['enable_file_collector'] = False
            elif memory.available > 2 * 1024 * 1024 * 1024:  # > 2GB
                self.logger.info("✅ High memory - enabling enhanced features")
                agent_config['event_batch_size'] = 20
                agent_config['event_queue_size'] = 1000
            
            # CPU-based optimizations
            if cpu_count < 2:
                self.logger.warning("⚠️ Limited CPU - applying CPU optimizations")
                agent_config['num_workers'] = 1
                agent_config['polling_interval'] = 60
            elif cpu_count >= 4:
                self.logger.info("✅ Multiple CPUs - enabling parallel processing")
                agent_config['num_workers'] = min(cpu_count, 4)
                agent_config['polling_interval'] = 30
            
            # Disk space optimizations
            disk = psutil.disk_usage('/')
            if disk.free < 1024 * 1024 * 1024:  # < 1GB
                self.logger.warning("⚠️ Low disk space - applying storage optimizations")
                logging_config = config.get('logging', {})
                logging_config['max_log_size'] = '10MB'
                logging_config['backup_count'] = 2
            
            self.logger.info("⚡ Runtime optimizations applied")
            
        except Exception as e:
            self.logger.error(f"❌ Error applying optimizations: {e}")
    
    async def start(self):
        """🚀 Start the Linux EDR Agent"""
        try:
            self.logger.info("🚀 Starting Linux EDR Agent...")
            
            # Start agent manager with timeout
            await asyncio.wait_for(self.agent_manager.start(), timeout=120)
            
            # Set running state
            self.is_running = True
            self.start_time = datetime.now()
            self.performance_stats['start_time'] = time.time()
            self.health_status['overall'] = 'running'
            
            # Start monitoring tasks
            monitoring_tasks = [
                asyncio.create_task(self._performance_monitor(), name="performance_monitor"),
                asyncio.create_task(self._health_monitor(), name="health_monitor"),
                asyncio.create_task(self._resource_monitor(), name="resource_monitor")
            ]
            
            self.logger.info("✅ Linux EDR Agent started successfully")
            self.logger.info("🔄 All monitoring systems active")
            self.logger.info("🛑 Press Ctrl+C to stop gracefully")
            
            # Wait for monitoring tasks
            await asyncio.gather(*monitoring_tasks, return_exceptions=True)
            
        except asyncio.TimeoutError:
            self.logger.error("❌ Start timeout (120s)")
            self.health_status['overall'] = 'start_timeout'
            raise Exception("Agent start timeout")
        except Exception as e:
            self.logger.error(f"❌ Start failed: {e}")
            self.health_status['overall'] = 'start_failed'
            raise
    
    async def stop(self):
        """🛑 Stop the Linux EDR Agent gracefully"""
        try:
            self.logger.info("🛑 Stopping Linux EDR Agent...")
            self.is_running = False
            self.health_status['overall'] = 'stopping'
            
            if self.agent_manager:
                self.logger.info("🛑 Stopping agent manager...")
                # Stop with timeout
                try:
                    await asyncio.wait_for(self.agent_manager.stop(), timeout=30)
                    self.logger.info("✅ Agent manager stopped")
                except asyncio.TimeoutError:
                    self.logger.warning("⚠️ Agent manager stop timeout - forcing stop")
                except Exception as e:
                    self.logger.error(f"❌ Error stopping agent manager: {e}")
            
            # Cancel all running tasks
            self.logger.info("🛑 Cancelling monitoring tasks...")
            for task in asyncio.all_tasks():
                if task is not asyncio.current_task():
                    task.cancel()
            
            # Wait for tasks to cancel
            try:
                await asyncio.wait_for(asyncio.gather(*asyncio.all_tasks(), return_exceptions=True), timeout=10)
            except asyncio.TimeoutError:
                self.logger.warning("⚠️ Task cancellation timeout")
            
            # Calculate final statistics
            if self.start_time:
                uptime = (datetime.now() - self.start_time).total_seconds()
                self.performance_stats['uptime_seconds'] = uptime
                
                self.logger.info("📊 Final Statistics:")
                self.logger.info(f"   ⏱️ Uptime: {uptime:.1f}s ({uptime/3600:.2f}h)")
                self.logger.info(f"   💾 Peak Memory: {self.performance_stats['memory_usage_mb']:.1f}MB")
                self.logger.info(f"   🔄 Peak CPU: {self.performance_stats['cpu_usage_percent']:.1f}%")
                self.logger.info(f"   📊 Events Processed: {self.performance_stats['events_processed']}")
            
            self.health_status['overall'] = 'stopped'
            self.logger.info("✅ Linux EDR Agent stopped successfully")
            
        except asyncio.TimeoutError:
            self.logger.error("❌ Stop timeout - forcing shutdown")
            self.health_status['overall'] = 'force_stopped'
        except Exception as e:
            self.logger.error(f"❌ Stop error: {e}")
            self.health_status['overall'] = 'stop_error'
    
    async def _performance_monitor(self):
        """📊 Monitor agent performance continuously"""
        self.logger.info("📊 Performance monitor started")
        
        try:
            while self.is_running and not self.shutdown_requested:
                try:
                    # Get current process metrics
                    current_process = psutil.Process()
                    cpu_percent = current_process.cpu_percent()
                    memory_info = current_process.memory_info()
                    memory_mb = memory_info.rss / 1024 / 1024
                    
                    # Update performance stats
                    self.performance_stats.update({
                        'memory_usage_mb': max(self.performance_stats['memory_usage_mb'], memory_mb),
                        'cpu_usage_percent': max(self.performance_stats['cpu_usage_percent'], cpu_percent),
                        'uptime_seconds': time.time() - self.performance_stats['start_time']
                    })
                    
                    # Alert on high resource usage
                    if cpu_percent > 50:
                        self.logger.warning(f"⚠️ High CPU usage: {cpu_percent:.1f}%")
                    
                    if memory_mb > 500:
                        self.logger.warning(f"⚠️ High memory usage: {memory_mb:.1f}MB")
                    
                    # Log performance summary every 10 minutes
                    if int(time.time()) % 600 == 0:
                        uptime_hours = self.performance_stats['uptime_seconds'] / 3600
                        self.logger.info("📊 Performance Summary:")
                        self.logger.info(f"   ⏱️ Uptime: {uptime_hours:.2f} hours")
                        self.logger.info(f"   💾 Memory: {memory_mb:.1f}MB")
                        self.logger.info(f"   🔄 CPU: {cpu_percent:.1f}%")
                        self.logger.info(f"   🏥 Health: {self.health_status['overall']}")
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Performance monitoring error: {e}")
                    await asyncio.sleep(60)
                    
        except asyncio.CancelledError:
            self.logger.info("📊 Performance monitor stopped")
        except Exception as e:
            self.logger.error(f"❌ Performance monitor failed: {e}")
    
    async def _health_monitor(self):
        """🏥 Monitor component health continuously"""
        self.logger.info("🏥 Health monitor started")
        
        try:
            while self.is_running and not self.shutdown_requested:
                try:
                    self.health_status['last_check'] = time.time()
                    
                    if self.agent_manager:
                        # Check agent manager health
                        if hasattr(self.agent_manager, 'get_status'):
                            try:
                                status = self.agent_manager.get_status()
                                self.health_status['components']['agent_manager'] = {
                                    'status': 'healthy' if status.get('is_running') else 'unhealthy',
                                    'details': status
                                }
                            except Exception as e:
                                self.health_status['components']['agent_manager'] = {
                                    'status': 'error',
                                    'error': str(e)
                                }
                        
                        # Check monitoring status
                        if hasattr(self.agent_manager, 'is_monitoring'):
                            if not self.agent_manager.is_monitoring:
                                self.logger.warning("⚠️ Agent monitoring inactive")
                                self.health_status['overall'] = 'monitoring_inactive'
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"❌ Health monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except asyncio.CancelledError:
            self.logger.info("🏥 Health monitor stopped")
        except Exception as e:
            self.logger.error(f"❌ Health monitor failed: {e}")
    
    async def _resource_monitor(self):
        """🔧 Monitor system resources and auto-adjust"""
        self.logger.info("🔧 Resource monitor started")
        
        try:
            while self.is_running and not self.shutdown_requested:
                try:
                    # Check system resources
                    memory = psutil.virtual_memory()
                    cpu_percent = psutil.cpu_percent(interval=1)
                    disk = psutil.disk_usage('/')
                    
                    # Auto-adjust based on resource pressure
                    if memory.percent > 95:
                        self.logger.critical("🚨 Critical memory usage > 95%")
                        # Could implement emergency shutdown
                    elif memory.percent > 85:
                        self.logger.warning("⚠️ High memory usage > 85%")
                    
                    if cpu_percent > 95:
                        self.logger.critical("🚨 Critical CPU usage > 95%")
                    elif cpu_percent > 80:
                        self.logger.warning("⚠️ High CPU usage > 80%")
                    
                    if disk.percent > 95:
                        self.logger.critical("🚨 Critical disk usage > 95%")
                    elif disk.percent > 85:
                        self.logger.warning("⚠️ High disk usage > 85%")
                    
                    await asyncio.sleep(120)  # Check every 2 minutes
                    
                except Exception as e:
                    self.logger.error(f"❌ Resource monitoring error: {e}")
                    await asyncio.sleep(120)
                    
        except asyncio.CancelledError:
            self.logger.info("🔧 Resource monitor stopped")
        except Exception as e:
            self.logger.error(f"❌ Resource monitor failed: {e}")
    
    def setup_signal_handlers(self):
        """🔔 Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            signal_name = signal.Signals(signum).name
            self.logger.info(f"🔔 Received signal {signal_name} ({signum})")
            
            if signum in [signal.SIGINT, signal.SIGTERM]:
                self.logger.info("🛑 Graceful shutdown requested")
                self.shutdown_requested = True
                self.is_running = False
                
                # Force exit if graceful shutdown takes too long
                def force_exit():
                    time.sleep(10)  # Wait 10 seconds for graceful shutdown
                    self.logger.warning("⚠️ Force shutdown after timeout")
                    os._exit(0)
                
                import threading
                force_thread = threading.Thread(target=force_exit, daemon=True)
                force_thread.start()
                
            elif signum == signal.SIGHUP:
                self.logger.info("🔄 Reload signal received")
                # Could implement configuration reload
        
        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGHUP, signal_handler)
        
        self.logger.info("🔔 Signal handlers configured")
        self.logger.info("💡 Press Ctrl+C to stop gracefully")

def parse_arguments():
    """📝 Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="🐧 Linux EDR Agent - Endpoint Detection and Response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run with default settings
  python main.py --debug            # Run with debug logging
  python main.py --config custom.yaml  # Use custom config file
  python main.py --check            # Check system requirements and exit
        """
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check system requirements and exit'
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version='Linux EDR Agent v2.1.0'
    )
    
    parser.add_argument(
        '--service',
        action='store_true',
        help='Run as system service (daemon mode)'
    )
    
    return parser.parse_args()

async def main():
    """🚀 Main entry point for Linux EDR Agent"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logging
    setup_production_logging(debug_mode=args.debug)
    logger = logging.getLogger(__name__)
    
    # Print banner
    print("=" * 80)
    print("🐧 Linux EDR Agent - Production Ready")
    print("   Endpoint Detection and Response Agent for Linux Systems")
    print("   Version: 2.1.0 | Platform: Linux")
    print("=" * 80)
    
    # Check system requirements
    if not check_system_requirements():
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # If only checking requirements, exit here
    if args.check:
        print("✅ All system requirements met")
        sys.exit(0)
    
    agent = None
    try:
        logger.info("🚀 Starting Linux EDR Agent...")
        
        # Create agent instance
        agent = LinuxEDRAgent(debug_mode=args.debug)
        
        # Setup signal handlers
        agent.setup_signal_handlers()
        
        # Initialize agent
        await agent.initialize()
        
        # Start agent
        await agent.start()
        
        # Main event loop
        while agent.is_running and not agent.shutdown_requested:
            try:
                await asyncio.sleep(1)
            except KeyboardInterrupt:
                logger.info("🔔 Keyboard interrupt received (Ctrl+C)")
                logger.info("🛑 Initiating graceful shutdown...")
                agent.shutdown_requested = True
                agent.is_running = False
                break
            except Exception as e:
                logger.error(f"❌ Main loop error: {e}")
                await asyncio.sleep(5)
        
        # Wait for graceful shutdown with timeout
        if agent.shutdown_requested:
            logger.info("⏳ Waiting for graceful shutdown...")
            try:
                # Wait up to 15 seconds for graceful shutdown
                shutdown_start = time.time()
                while agent.is_running and (time.time() - shutdown_start) < 15:
                    await asyncio.sleep(0.5)
                
                if agent.is_running:
                    logger.warning("⚠️ Graceful shutdown timeout - forcing stop")
            except Exception as e:
                logger.error(f"❌ Error during shutdown wait: {e}")
        
    except KeyboardInterrupt:
        logger.info("🔔 Interrupted by user (Ctrl+C)")
        if agent:
            agent.shutdown_requested = True
            agent.is_running = False
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        if args.debug:
            import traceback
            logger.debug(f"🔍 Full traceback:\n{traceback.format_exc()}")
        return 1
    finally:
        if agent:
            try:
                logger.info("🛑 Stopping agent components...")
                await agent.stop()
            except Exception as e:
                logger.error(f"❌ Error during shutdown: {e}")
    
    logger.info("👋 Linux EDR Agent shutdown complete")
    return 0

if __name__ == "__main__":
    try:
        # Handle different execution contexts
        if os.environ.get('EDR_AGENT_MODE') == 'service':
            # Running as systemd service
            print("🔧 Starting in service mode...")
        
        # Run the main function
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user (Ctrl+C)")
        print("👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        if '--debug' in sys.argv:
            import traceback
            print(f"🔍 Full traceback:\n{traceback.format_exc()}")
        sys.exit(1)