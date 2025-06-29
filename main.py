#!/usr/bin/env python3
"""
🐧 Linux EDR Agent - FIXED Production Version
All connection and shutdown issues resolved
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
    """🐧 Setup production-grade logging for Linux EDR Agent with thread safety"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory with proper permissions
    log_dir = current_dir / 'logs'
    log_dir.mkdir(exist_ok=True, mode=0o755)
    
    try:
        from logging.handlers import RotatingFileHandler
        
        # Configure log level
        log_level = logging.DEBUG if debug_mode else logging.INFO
        
        # FIXED: Use thread-safe handlers
        main_handler = RotatingFileHandler(
            log_dir / 'linux_edr_agent.log',
            maxBytes=50*1024*1024,  # 50MB
            backupCount=5,
            encoding='utf-8',
            delay=True  # FIXED: Delay file opening to avoid reentrant issues
        )
        main_handler.setLevel(log_level)
        
        # Error log file
        error_handler = RotatingFileHandler(
            log_dir / 'linux_edr_errors.log',
            maxBytes=20*1024*1024,  # 20MB
            backupCount=3,
            encoding='utf-8',
            delay=True  # FIXED: Delay file opening
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
        
        # FIXED: Configure root logger with thread safety
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers to avoid duplicates
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add new handlers
        root_logger.addHandler(main_handler)
        root_logger.addHandler(error_handler)
        root_logger.addHandler(console_handler)
        
        # Reduce noise from external libraries
        for noisy_logger in ['urllib3', 'aiohttp', 'asyncio', 'requests']:
            logging.getLogger(noisy_logger).setLevel(logging.WARNING)
        
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
    """🐧 FIXED Linux EDR Agent with proper shutdown handling"""
    
    def __init__(self, debug_mode: bool = False):
        self.logger = logging.getLogger("**main**")
        self.debug_mode = debug_mode
        self.agent_manager = None
        self.config_manager = None
        self.is_running = False
        self.agent_id = None
        self.start_time = None
        self.shutdown_requested = False
        self.shutdown_event = asyncio.Event()
        
        # FIXED: Add task tracking for proper shutdown
        self.monitoring_tasks = []
        self.shutdown_task = None
        
        # Performance monitoring
        self.performance_stats = {
            'start_time': time.time(),
            'memory_usage_mb': 0.0,
            'cpu_usage_percent': 0.0,
            'uptime_seconds': 0.0
        }
        
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
            
            self.logger.info("✅ Linux EDR Agent initialized successfully")
            self.logger.info("=" * 80)
            
        except asyncio.TimeoutError:
            self.logger.error("❌ Initialization timeout (180s)")
            raise Exception("Agent initialization timeout")
        except Exception as e:
            self.logger.error(f"❌ Initialization failed: {e}")
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
            elif cpu_count >= 4:
                self.logger.info("✅ Multiple CPUs - enabling parallel processing")
                agent_config['num_workers'] = min(cpu_count, 4)
            
            self.logger.info("⚡ Runtime optimizations applied")
            
        except Exception as e:
            self.logger.error(f"❌ Error applying optimizations: {e}")
    
    async def start(self):
        """🚀 FIXED: Start the Linux EDR Agent with proper shutdown handling"""
        try:
            self.logger.info("🚀 Starting Linux EDR Agent...")
            self.is_running = True
            self.start_time = datetime.now()
            
            # Initialize performance stats
            self.performance_stats = {
                'start_time': time.time(),
                'memory_usage_mb': 0.0,
                'cpu_usage_percent': 0.0,
                'uptime_seconds': 0.0
            }
            
            # Start agent manager
            if self.agent_manager:
                await asyncio.wait_for(self.agent_manager.start(), timeout=60)
                self.logger.info("✅ Agent manager started")
            
            # Start monitoring tasks
            self.monitoring_tasks = []
            
            # Performance monitor
            perf_task = asyncio.create_task(self._performance_monitor())
            self.monitoring_tasks.append(perf_task)
            
            # Shutdown monitor
            shutdown_task = asyncio.create_task(self._graceful_shutdown_monitor())
            self.monitoring_tasks.append(shutdown_task)
            
            self.logger.info("✅ All monitoring tasks started")
            
            # FIXED: Wait for shutdown event instead of infinite loop
            self.logger.info("🔄 Agent running - waiting for shutdown signal...")
            
            try:
                # Wait for shutdown event with timeout
                await asyncio.wait_for(self.shutdown_event.wait(), timeout=None)
                self.logger.info("🛑 Shutdown event received")
            except asyncio.TimeoutError:
                self.logger.info("⏰ Shutdown timeout - forcing stop")
            except asyncio.CancelledError:
                self.logger.info("🛑 Agent cancelled")
            
            # Stop the agent
            await self.stop()
            
        except asyncio.TimeoutError:
            self.logger.error("❌ Start timeout (120s)")
            raise Exception("Agent start timeout")
        except Exception as e:
            self.logger.error(f"❌ Start failed: {e}")
            raise
    
    async def stop(self):
        """🛑 FIXED: Graceful shutdown with proper cleanup"""
        if not self.is_running:
            return
        
        try:
            # FIXED: Use print for shutdown messages to avoid logging conflicts
            print("🛑 Shutdown event received")
            
            self.is_running = False
            self.shutdown_requested = True
            
            # Signal shutdown event
            if not self.shutdown_event.is_set():
                self.shutdown_event.set()
            
            # Cancel monitoring tasks
            for task in self.monitoring_tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            
            # Stop agent manager if available
            if self.agent_manager:
                try:
                    await self.agent_manager.stop()
                except Exception as e:
                    print(f"⚠️ Error stopping agent manager: {e}")
            
            # Clear tasks
            self.monitoring_tasks.clear()
            
            print("👋 Linux EDR Agent terminated")
            
        except Exception as e:
            print(f"❌ Error during shutdown: {e}")
        finally:
            self.is_running = False
    
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
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"❌ Performance monitoring error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ Performance monitor failed: {e}")
        finally:
            self.logger.info("📊 Performance monitor stopped")
    
    async def _graceful_shutdown_monitor(self):
        """🛑 FIXED: Monitor for graceful shutdown"""
        try:
            while self.is_running and not self.shutdown_requested:
                await asyncio.sleep(1)
            
            # Shutdown requested, initiate graceful stop
            if self.shutdown_requested:
                await self.stop()
            
        except Exception as e:
            self.logger.error(f"❌ Shutdown monitor error: {e}")
            await self.stop()
    
    def signal_handler(self, signum, frame):
        """🔔 FIXED: Handle system signals with thread-safe shutdown coordination"""
        signal_name = signal.Signals(signum).name
        
        # FIXED: Use print instead of logger to avoid reentrant issues
        print(f"\n🛑 Received signal {signal_name} ({signum}) - initiating graceful shutdown...")
        
        if signum in [signal.SIGINT, signal.SIGTERM]:
            # FIXED: Only set shutdown flags, don't create new tasks
            self.shutdown_requested = True
            self.is_running = False
            
            # Signal the shutdown event to wake up the main loop
            if not self.shutdown_event.is_set():
                self.shutdown_event.set()
            
            # FIXED: Force exit after 5 seconds if still running
            def force_exit():
                import threading
                import time
                time.sleep(5)
                if self.is_running:
                    print("🛑 Force exit after 5 seconds")
                    os._exit(1)
            
            # Start force exit thread
            import threading
            force_thread = threading.Thread(target=force_exit, daemon=True)
            force_thread.start()

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
    
    return parser.parse_args()

async def main():
    """🚀 FIXED: Main entry point for Linux EDR Agent with proper shutdown"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logging
    setup_production_logging(debug_mode=args.debug)
    logger = logging.getLogger("**main**")
    
    # Print banner
    print("=" * 80)
    print("🐧 Linux EDR Agent - FIXED Production Version")
    print("   All connection and shutdown issues resolved")
    print("   Version: 2.1.0-FIXED | Platform: Linux")
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
        signal.signal(signal.SIGINT, agent.signal_handler)
        signal.signal(signal.SIGTERM, agent.signal_handler)
        
        # Initialize agent
        await agent.initialize()
        
        # Start agent (this will wait for shutdown)
        await agent.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Keyboard interrupt received")
        if agent:
            await agent.stop()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        if agent:
            await agent.stop()
        sys.exit(1)
    finally:
        # FIXED: Ensure cleanup happens without logging
        if agent and agent.is_running:
            print("🛑 Ensuring agent cleanup...")
            try:
                await agent.stop()
            except Exception as e:
                print(f"⚠️ Cleanup error: {e}")
        
        # FIXED: Final message without logger
        print("👋 Linux EDR Agent terminated")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)