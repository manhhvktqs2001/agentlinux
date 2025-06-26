#!/usr/bin/env python3
"""
Linux EDR Agent - Main Entry Point (FIXED)
Interactive mode with console output and better error handling
"""

import asyncio
import logging
import signal
import sys
import os
import time
import threading
from pathlib import Path
from datetime import datetime

# Global pause state
PAUSED = False
PAUSE_LOCK = threading.Lock()

def check_root_privileges():
    """Check if running with root privileges"""
    if os.geteuid() != 0:
        print("=" * 60)
        print("❌ ERROR: Linux EDR Agent requires root privileges")
        print("=" * 60)
        print("The EDR Agent needs root access to monitor:")
        print("  - Process activities across all users")
        print("  - Network connections and traffic")
        print("  - File system changes in protected areas")
        print("  - Authentication events and logs")
        print("  - System events and kernel activities")
        print("  - Container and service activities")
        print("=" * 60)
        print("Please run with sudo:")
        print(f"  sudo python3 {sys.argv[0]}")
        print("=" * 60)
        print("📋 Quick Fix Commands:")
        print("  # Install dependencies first:")
        print("  sudo apt update && sudo apt install python3-pip python3-psutil python3-aiohttp python3-yaml")
        print("  # Or for RedHat/CentOS:")
        print("  sudo yum install python3-pip python3-psutil python3-aiohttp python3-pyyaml")
        print("  # Then run the agent:")
        print(f"  sudo python3 {sys.argv[0]}")
        print("=" * 60)
        sys.exit(1)
    else:
        print("=" * 60)
        print("✅ Linux EDR Agent - Running with Root Privileges")
        print("=" * 60)
        print("Enhanced monitoring capabilities enabled:")
        print("  - Process monitoring with elevated access")
        print("  - Network connection monitoring")
        print("  - File system monitoring (including system files)")
        print("  - Authentication and user activity monitoring")
        print("  - System service and daemon monitoring")
        print("  - Container monitoring (Docker/Podman)")
        print("  - Audit log monitoring")
        print("  - Syslog monitoring")
        print("=" * 60)

def setup_imports():
    """Setup import paths for Linux agent"""
    try:
        # Get current directory
        current_dir = Path(__file__).parent.absolute()
        
        # Add current directory to Python path
        if str(current_dir) not in sys.path:
            sys.path.insert(0, str(current_dir))
        
        # Add agent directory to Python path
        agent_dir = current_dir / 'agent'
        if str(agent_dir) not in sys.path:
            sys.path.insert(0, str(agent_dir))
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to setup imports: {e}")
        return False

def setup_logging():
    """Setup enhanced logging configuration for Linux"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory if it doesn't exist
    log_dir = Path(__file__).parent / 'logs'
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging with UTF-8 encoding
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_dir / 'linux_edr_agent.log', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific log levels for noisy modules
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

def check_dependencies():
    """Check if required Python modules are available"""
    required_modules = {
        'psutil': 'python3-psutil',
        'aiohttp': 'python3-aiohttp', 
        'yaml': 'python3-yaml',
        'asyncio': 'built-in'
    }
    
    missing_modules = []
    
    for module, package in required_modules.items():
        try:
            if module == 'yaml':
                import yaml
            else:
                __import__(module)
        except ImportError:
            missing_modules.append((module, package))
    
    if missing_modules:
        print("❌ Missing required Python modules:")
        for module, package in missing_modules:
            print(f"   - {module} (install: {package})")
        print("\n📦 Install missing dependencies:")
        print("   # Ubuntu/Debian:")
        print("   sudo apt update")
        print("   sudo apt install " + " ".join([pkg for _, pkg in missing_modules if pkg != 'built-in']))
        print("\n   # RedHat/CentOS:")
        print("   sudo yum install " + " ".join([pkg for _, pkg in missing_modules if pkg != 'built-in']))
        print("\n   # Or using pip:")
        print("   sudo pip3 install " + " ".join([mod for mod, _ in missing_modules if _ != 'built-in']))
        return False
    
    return True

def create_required_files():
    """Create required configuration files if they don't exist"""
    try:
        # Create config directory
        config_dir = Path(__file__).parent / 'config'
        config_dir.mkdir(exist_ok=True)
        
        # Create basic config file if it doesn't exist
        config_file = config_dir / 'agent_config.yaml'
        if not config_file.exists():
            print("📋 Creating basic configuration file...")
            basic_config = """# Basic Linux EDR Agent Configuration
agent:
  name: 'EDR-Agent-Linux'
  version: '2.1.0-Linux'
  platform: 'linux'
  heartbeat_interval: 30

server:
  host: 'localhost'
  port: 5000
  auth_token: 'edr_agent_auth_2024'

collection:
  enabled: true
  collect_processes: true
  collect_files: true
  collect_network: true

logging:
  level: 'INFO'
  console_enabled: true
  log_directory: './logs'
"""
            with open(config_file, 'w') as f:
                f.write(basic_config)
            print(f"✅ Created basic config: {config_file}")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to create required files: {e}")
        return False

class LinuxEDRAgent:
    """Linux EDR Agent with continuous monitoring capabilities"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.agent_manager = None
        self.config_manager = None
        self.is_running = False
        self.start_time = None
        
        # Linux-specific information
        self.system_info = self._get_linux_system_info()
        
        # Performance tracking
        self.performance_stats = {
            'start_time': None,
            'events_collected': 0,
            'events_sent': 0,
            'alerts_received': 0,
            'uptime': 0
        }
    
    def _get_linux_system_info(self):
        """Get Linux system information"""
        try:
            info = {
                'hostname': os.uname().nodename,
                'kernel': os.uname().release,
                'architecture': os.uname().machine,
                'distribution': 'Unknown',
                'version': 'Unknown'
            }
            
            # Try to get distribution info
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('NAME='):
                            info['distribution'] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('VERSION='):
                            info['version'] = line.split('=')[1].strip().strip('"')
            except:
                pass
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    async def initialize(self):
        """Initialize Linux EDR agent"""
        try:
            self.logger.info("🐧 Initializing Linux EDR Agent...")
            self.logger.info("=" * 60)
            
            # Log system information
            self.logger.info(f"🖥️  Hostname: {self.system_info.get('hostname', 'Unknown')}")
            self.logger.info(f"🐧 Distribution: {self.system_info.get('distribution', 'Unknown')} {self.system_info.get('version', '')}")
            self.logger.info(f"⚙️  Kernel: {self.system_info.get('kernel', 'Unknown')}")
            self.logger.info(f"🏗️  Architecture: {self.system_info.get('architecture', 'Unknown')}")
            
            # Confirm root privileges
            self.logger.info("✅ Running with root privileges - Full monitoring enabled")
            
            try:
                # Import required modules with better error handling
                from agent.core.config_manager import ConfigManager
                from agent.core.agent_manager import LinuxAgentManager
                
                # Setup configuration
                self.logger.info("📋 Creating configuration manager...")
                self.config_manager = ConfigManager()
                
                self.logger.info("📋 Loading Linux-specific configuration...")
                await self.config_manager.load_config()
                
                # Initialize agent manager
                self.logger.info("🎯 Creating Linux agent manager...")
                self.agent_manager = LinuxAgentManager(self.config_manager)
                
                self.logger.info("🎯 Initializing Linux agent manager...")
                await self.agent_manager.initialize()
                
            except ImportError as e:
                self.logger.error(f"❌ Import error: {e}")
                self.logger.error("💡 This usually means missing dependencies or incorrect file structure")
                self.logger.error("   Check that all required files are present and dependencies are installed")
                raise
            except Exception as e:
                self.logger.error(f"❌ Configuration error: {e}")
                self.logger.error("💡 Check your configuration files and file permissions")
                raise
            
            self.logger.info("✅ Linux EDR Agent initialized successfully")
            self.logger.info("=" * 60)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Linux EDR Agent: {e}")
            self.logger.error("🔧 Troubleshooting steps:")
            self.logger.error("   1. Check all dependencies are installed")
            self.logger.error("   2. Verify configuration files exist")
            self.logger.error("   3. Check file permissions")
            self.logger.error("   4. Ensure running with root privileges")
            raise
    
    async def start(self):
        """Start Linux EDR agent with continuous monitoring"""
        try:
            self.logger.info("🚀 Starting Linux EDR Agent with continuous monitoring...")
            self.logger.info("📊 Linux Monitoring: Process, Network, System, File, Auth, Container, Audit")
            self.logger.info("⚡ Enhanced polling intervals for real-time data collection")
            self.logger.info("🔔 Linux security notifications enabled")
            self.logger.info("🐧 Platform-specific monitoring active")
            self.logger.info("=" * 60)
            
            # Start agent
            await self.agent_manager.start()
            
            # Set running state
            self.is_running = True
            self.start_time = time.time()
            self.performance_stats['start_time'] = self.start_time
            
            self.logger.info("✅ Linux EDR Agent started successfully")
            self.logger.info("🔄 Continuous monitoring active - Press Ctrl+C to stop")
            self.logger.info("=" * 60)
            
            # Start performance monitoring
            asyncio.create_task(self._performance_monitoring_loop())
            
            # Start statistics logging
            asyncio.create_task(self._statistics_logging_loop())
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start Linux EDR Agent: {e}")
            raise
    
    async def stop(self):
        """Stop Linux EDR agent gracefully"""
        try:
            self.logger.info("🛑 Stopping Linux EDR Agent...")
            
            # Set running state
            self.is_running = False
            
            # Stop agent manager
            if self.agent_manager:
                await self.agent_manager.stop()
            
            # Calculate final statistics
            if self.start_time:
                uptime = time.time() - self.start_time
                self.performance_stats['uptime'] = uptime
                
                self.logger.info("📊 Final Performance Statistics:")
                self.logger.info(f"   ⏱️ Total Uptime: {uptime:.1f} seconds ({uptime/3600:.2f} hours)")
                self.logger.info(f"   📥 Events Collected: {self.performance_stats['events_collected']}")
                self.logger.info(f"   📤 Events Sent: {self.performance_stats['events_sent']}")
                self.logger.info(f"   🚨 Alerts Received: {self.performance_stats['alerts_received']}")
                
                if uptime > 0:
                    events_per_second = self.performance_stats['events_collected'] / uptime
                    self.logger.info(f"   📈 Average Events/Second: {events_per_second:.2f}")
            
            self.logger.info("✅ Linux EDR Agent stopped successfully")
            self.logger.info("=" * 60)
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping Linux EDR Agent: {e}")
    
    async def _performance_monitoring_loop(self):
        """Monitor agent performance continuously"""
        try:
            while self.is_running:
                try:
                    # Get current statistics
                    if self.agent_manager and hasattr(self.agent_manager, 'event_processor') and self.agent_manager.event_processor:
                        stats = self.agent_manager.event_processor.get_stats()
                        
                        # Update performance stats
                        self.performance_stats['events_collected'] = stats.get('events_collected', 0)
                        self.performance_stats['events_sent'] = stats.get('events_sent', 0)
                        self.performance_stats['alerts_received'] = stats.get('alerts_received', 0)
                        
                        # Check for performance issues
                        queue_utilization = stats.get('queue_utilization', 0)
                        if queue_utilization > 0.8:  # 80% full
                            self.logger.warning(f"⚠️ Event queue utilization high: {queue_utilization:.1%}")
                        
                        processing_rate = stats.get('processing_rate', 0)
                        if processing_rate < 0.1:
                            self.logger.warning(f"⚠️ Low processing rate: {processing_rate:.2f} events/sec")
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"❌ Performance monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self.logger.error(f"❌ Performance monitoring loop failed: {e}")
    
    async def _statistics_logging_loop(self):
        """Log agent statistics periodically"""
        try:
            while self.is_running:
                try:
                    # Calculate uptime
                    if self.start_time:
                        uptime = time.time() - self.start_time
                        self.performance_stats['uptime'] = uptime
                    
                    # Log statistics every 5 minutes
                    if int(time.time()) % 300 == 0:  # Every 5 minutes
                        self.logger.info("📊 Linux Agent Statistics:")
                        self.logger.info(f"   ⏱️ Uptime: {uptime:.1f} seconds")
                        self.logger.info(f"   📥 Events Collected: {self.performance_stats['events_collected']}")
                        self.logger.info(f"   📤 Events Sent: {self.performance_stats['events_sent']}")
                        self.logger.info(f"   🚨 Alerts Received: {self.performance_stats['alerts_received']}")
                        self.logger.info(f"   🐧 Platform: Linux ({self.system_info.get('distribution', 'Unknown')})")
                        
                        if self.agent_manager:
                            agent_stats = self.agent_manager.get_status()
                            self.logger.info(f"   🎯 Agent Status: {agent_stats.get('is_monitoring', 'Unknown')}")
                            self.logger.info(f"   🆔 Agent ID: {agent_stats.get('agent_id', 'Unknown')}")
                        
                        self.logger.info("-" * 40)
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Statistics logging error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ Statistics logging loop failed: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        self.logger.info(f"🛑 Received signal {signum}, stopping agent...")
        asyncio.create_task(self.stop())

async def main():
    """Main function to run the Linux agent"""
    # Setup logging first
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("📝 Linux agent logging setup completed")
    
    # Create agent instance
    logger.info("🎯 Creating Linux agent instance...")
    agent = LinuxEDRAgent()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, agent.signal_handler)
    signal.signal(signal.SIGTERM, agent.signal_handler)
    logger.info("🔧 Signal handlers configured")
    
    try:
        # Initialize agent
        logger.info("🚀 Initializing Linux agent...")
        await agent.initialize()
        
        # Start agent
        logger.info("▶️ Starting Linux agent...")
        await agent.start()
        
        # Main monitoring loop
        while agent.is_running:
            try:
                # Normal monitoring - just keep the agent running
                await asyncio.sleep(1)
                
                # Log status every 30 seconds
                if int(asyncio.get_event_loop().time()) % 30 == 0:
                    logger.info("🔄 Linux agent running - monitoring system activities...")
                
            except KeyboardInterrupt:
                print("\n🛑 Keyboard interrupt received. Stopping Linux agent...")
                break
            except Exception as e:
                logger.error(f"❌ Main loop error: {e}")
                await asyncio.sleep(5)  # Wait before retrying
        
    except KeyboardInterrupt:
        logger.info("🛑 Received interrupt signal, stopping Linux agent...")
    except Exception as e:
        logger.error(f"❌ Linux agent error: {e}", exc_info=True)
        logger.error("🔧 Check the troubleshooting section in the documentation")
    finally:
        await agent.stop()

if __name__ == "__main__":
    try:
        print("🚀 Starting Linux EDR Agent...")
        print("=" * 60)
        
        # Check root privileges first
        check_root_privileges()
        
        # Check dependencies
        print("🔍 Checking dependencies...")
        if not check_dependencies():
            print("❌ Missing dependencies. Please install them first.")
            sys.exit(1)
        
        # Setup imports
        print("🔧 Setting up import paths...")
        if not setup_imports():
            print("❌ Failed to setup import paths")
            sys.exit(1)
        
        # Create required files
        print("📁 Creating required files...")
        if not create_required_files():
            print("❌ Failed to create required files")
            sys.exit(1)
        
        print("✅ All checks passed. Starting agent...")
        print("=" * 60)
        
        # Run the agent
        asyncio.run(main())
        
    except KeyboardInterrupt:
        print("\n🛑 Linux agent stopped by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        print("\n" + "=" * 60)
        print("🔄 Linux agent execution completed")
        print("=" * 60)