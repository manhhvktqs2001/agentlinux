# agent/collectors/container_collector.py - Linux Container Collector
"""
Linux Container Collector - Monitor Docker and Podman containers
Enhanced security monitoring for containerized environments
"""

import asyncio
import logging
import time
import json
import subprocess
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from agent.collectors.base_collector import BaseCollector
from agent.schemas.events import EventData, EventType, EventSeverity

@dataclass
class ContainerInfo:
    """Container information structure"""
    id: str
    name: str
    image: str
    status: str
    created: str
    ports: List[str]
    mounts: List[str]
    networks: List[str]
    command: str
    user: str
    privileged: bool
    security_opts: List[str]
    capabilities: List[str]
    pid: Optional[int] = None
    memory_usage: Optional[int] = None
    cpu_usage: Optional[float] = None
    network_usage: Optional[Dict[str, int]] = None

class LinuxContainerCollector(BaseCollector):
    """Linux Container Collector - Monitor Docker and Podman containers"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "container")
        self.logger = logging.getLogger(__name__)
        
        # Container runtime detection
        self.docker_available = False
        self.podman_available = False
        self.container_runtime = None
        
        # Container tracking
        self.known_containers = {}
        self.container_events = []
        
        # Security monitoring
        self.security_events = []
        self.privileged_containers = []
        self.suspicious_containers = []
        
        # Performance tracking
        self.stats_collection_enabled = True
        self.last_stats_collection = 0
        
        # Configuration
        self.monitor_docker = True
        self.monitor_podman = True
        self.collect_stats = True
        self.security_scanning = True
        
    async def initialize(self):
        """Initialize container collector"""
        try:
            self.logger.info("🐳 Initializing Linux Container Collector...")
            
            # Detect container runtimes
            await self._detect_container_runtimes()
            
            if not self.docker_available and not self.podman_available:
                self.logger.warning("⚠️ No container runtime detected (Docker/Podman)")
                return
            
            # Initialize container tracking
            await self._initialize_container_tracking()
            
            # Setup security monitoring
            if self.security_scanning:
                await self._setup_security_monitoring()
            
            self.logger.info(f"✅ Container Collector initialized - Runtime: {self.container_runtime}")
            
        except Exception as e:
            self.logger.error(f"❌ Container Collector initialization failed: {e}")
            raise
    
    async def _detect_container_runtimes(self):
        """Detect available container runtimes"""
        try:
            # Check Docker
            try:
                result = subprocess.run(
                    ['docker', '--version'], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                if result.returncode == 0:
                    self.docker_available = True
                    self.container_runtime = 'docker'
                    self.logger.info(f"🐳 Docker detected: {result.stdout.strip()}")
            except:
                pass
            
            # Check Podman
            try:
                result = subprocess.run(
                    ['podman', '--version'], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                if result.returncode == 0:
                    self.podman_available = True
                    if not self.docker_available:
                        self.container_runtime = 'podman'
                    self.logger.info(f"📦 Podman detected: {result.stdout.strip()}")
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"❌ Container runtime detection failed: {e}")
    
    async def _initialize_container_tracking(self):
        """Initialize container tracking"""
        try:
            # Get initial container list
            containers = await self._get_all_containers()
            
            for container in containers:
                self.known_containers[container.id] = {
                    'info': container,
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'status_history': [container.status],
                    'security_events': []
                }
            
            self.logger.info(f"📊 Tracking {len(self.known_containers)} containers")
            
        except Exception as e:
            self.logger.error(f"❌ Container tracking initialization failed: {e}")
    
    async def _setup_security_monitoring(self):
        """Setup security monitoring for containers"""
        try:
            # Check for privileged containers
            privileged_containers = await self._find_privileged_containers()
            
            for container in privileged_containers:
                await self._report_security_event(
                    container_id=container.id,
                    event_type="privileged_container_detected",
                    severity=EventSeverity.HIGH,
                    details={
                        'container_name': container.name,
                        'privileged': container.privileged,
                        'security_opts': container.security_opts,
                        'capabilities': container.capabilities
                    }
                )
            
            # Check for suspicious containers
            suspicious_containers = await self._find_suspicious_containers()
            
            for container in suspicious_containers:
                await self._report_security_event(
                    container_id=container.id,
                    event_type="suspicious_container_detected",
                    severity=EventSeverity.MEDIUM,
                    details={
                        'container_name': container.name,
                        'suspicious_factors': container.security_opts
                    }
                )
            
        except Exception as e:
            self.logger.error(f"❌ Security monitoring setup failed: {e}")
    
    async def collect_data(self):
        """Collect container data"""
        try:
            if not self.is_running:
                return
            
            # Get current containers
            current_containers = await self._get_all_containers()
            current_container_ids = {c.id for c in current_containers}
            
            # Check for new containers
            for container in current_containers:
                if container.id not in self.known_containers:
                    await self._handle_new_container(container)
                else:
                    await self._update_container_info(container)
            
            # Check for stopped/removed containers
            known_ids = set(self.known_containers.keys())
            removed_ids = known_ids - current_container_ids
            
            for container_id in removed_ids:
                await self._handle_removed_container(container_id)
            
            # Collect performance stats
            if self.collect_stats and time.time() - self.last_stats_collection > 30:
                await self._collect_container_stats()
                self.last_stats_collection = time.time()
            
            # Security scanning
            if self.security_scanning:
                await self._perform_security_scan()
            
        except Exception as e:
            self.logger.error(f"❌ Container data collection failed: {e}")
    
    async def _get_all_containers(self) -> List[ContainerInfo]:
        """Get all running and stopped containers"""
        containers = []
        
        try:
            if self.docker_available:
                docker_containers = await self._get_docker_containers()
                containers.extend(docker_containers)
            
            if self.podman_available:
                podman_containers = await self._get_podman_containers()
                containers.extend(podman_containers)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to get containers: {e}")
        
        return containers
    
    async def _get_docker_containers(self) -> List[ContainerInfo]:
        """Get Docker containers"""
        containers = []
        
        try:
            # Get container list
            result = subprocess.run(
                ['docker', 'ps', '-a', '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            container = self._parse_docker_container(data)
                            if container:
                                containers.append(container)
                        except json.JSONDecodeError:
                            continue
            
        except Exception as e:
            self.logger.error(f"❌ Docker container listing failed: {e}")
        
        return containers
    
    async def _get_podman_containers(self) -> List[ContainerInfo]:
        """Get Podman containers"""
        containers = []
        
        try:
            # Get container list
            result = subprocess.run(
                ['podman', 'ps', '-a', '--format', 'json'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            container = self._parse_podman_container(data)
                            if container:
                                containers.append(container)
                        except json.JSONDecodeError:
                            continue
            
        except Exception as e:
            self.logger.error(f"❌ Podman container listing failed: {e}")
        
        return containers
    
    def _parse_docker_container(self, data: Dict) -> Optional[ContainerInfo]:
        """Parse Docker container data"""
        try:
            return ContainerInfo(
                id=data.get('ID', ''),
                name=data.get('Names', ''),
                image=data.get('Image', ''),
                status=data.get('Status', ''),
                created=data.get('CreatedAt', ''),
                ports=data.get('Ports', '').split(',') if data.get('Ports') else [],
                mounts=data.get('Mounts', '').split(',') if data.get('Mounts') else [],
                networks=data.get('Networks', '').split(',') if data.get('Networks') else [],
                command=data.get('Command', ''),
                user=data.get('User', ''),
                privileged=data.get('Privileged', 'false').lower() == 'true',
                security_opts=data.get('SecurityOpts', '').split(',') if data.get('SecurityOpts') else [],
                capabilities=data.get('Capabilities', '').split(',') if data.get('Capabilities') else []
            )
        except Exception as e:
            self.logger.debug(f"Failed to parse Docker container: {e}")
            return None
    
    def _parse_podman_container(self, data: Dict) -> Optional[ContainerInfo]:
        """Parse Podman container data"""
        try:
            return ContainerInfo(
                id=data.get('Id', ''),
                name=data.get('Names', ''),
                image=data.get('Image', ''),
                status=data.get('Status', ''),
                created=data.get('Created', ''),
                ports=data.get('Ports', []),
                mounts=data.get('Mounts', []),
                networks=data.get('Networks', []),
                command=data.get('Command', ''),
                user=data.get('User', ''),
                privileged=data.get('Privileged', False),
                security_opts=data.get('SecurityOpts', []),
                capabilities=data.get('Capabilities', [])
            )
        except Exception as e:
            self.logger.debug(f"Failed to parse Podman container: {e}")
            return None
    
    async def _handle_new_container(self, container: ContainerInfo):
        """Handle new container detection"""
        try:
            self.logger.info(f"🆕 New container detected: {container.name} ({container.id[:12]})")
            
            # Add to tracking
            self.known_containers[container.id] = {
                'info': container,
                'first_seen': datetime.now(),
                'last_seen': datetime.now(),
                'status_history': [container.status],
                'security_events': []
            }
            
            # Create event
            event_data = EventData(
                event_type=EventType.CONTAINER_CREATED,
                severity=EventSeverity.INFO,
                source="container_collector",
                data={
                    'container_id': container.id,
                    'container_name': container.name,
                    'image': container.image,
                    'status': container.status,
                    'runtime': self.container_runtime,
                    'privileged': container.privileged,
                    'security_opts': container.security_opts,
                    'capabilities': container.capabilities
                }
            )
            
            await self._send_event(event_data)
            
            # Security check
            if container.privileged:
                await self._report_security_event(
                    container_id=container.id,
                    event_type="new_privileged_container",
                    severity=EventSeverity.HIGH,
                    details={'container_name': container.name}
                )
            
        except Exception as e:
            self.logger.error(f"❌ New container handling failed: {e}")
    
    async def _update_container_info(self, container: ContainerInfo):
        """Update existing container information"""
        try:
            if container.id in self.known_containers:
                tracking_info = self.known_containers[container.id]
                old_status = tracking_info['info'].status
                
                # Update tracking info
                tracking_info['info'] = container
                tracking_info['last_seen'] = datetime.now()
                tracking_info['status_history'].append(container.status)
                
                # Check for status change
                if old_status != container.status:
                    self.logger.info(f"🔄 Container status changed: {container.name} ({container.id[:12]}) - {old_status} -> {container.status}")
                    
                    event_data = EventData(
                        event_type=EventType.CONTAINER_STATUS_CHANGED,
                        severity=EventSeverity.INFO,
                        source="container_collector",
                        data={
                            'container_id': container.id,
                            'container_name': container.name,
                            'old_status': old_status,
                            'new_status': container.status,
                            'runtime': self.container_runtime
                        }
                    )
                    
                    await self._send_event(event_data)
        
        except Exception as e:
            self.logger.error(f"❌ Container info update failed: {e}")
    
    async def _handle_removed_container(self, container_id: str):
        """Handle container removal"""
        try:
            if container_id in self.known_containers:
                container_info = self.known_containers[container_id]
                container_name = container_info['info'].name
                
                self.logger.info(f"🗑️ Container removed: {container_name} ({container_id[:12]})")
                
                # Create event
                event_data = EventData(
                    event_type=EventType.CONTAINER_REMOVED,
                    severity=EventSeverity.INFO,
                    source="container_collector",
                    data={
                        'container_id': container_id,
                        'container_name': container_name,
                        'runtime': self.container_runtime,
                        'lifetime_seconds': (datetime.now() - container_info['first_seen']).total_seconds()
                    }
                )
                
                await self._send_event(event_data)
                
                # Remove from tracking
                del self.known_containers[container_id]
        
        except Exception as e:
            self.logger.error(f"❌ Container removal handling failed: {e}")
    
    async def _collect_container_stats(self):
        """Collect container performance statistics"""
        try:
            for container_id, tracking_info in self.known_containers.items():
                container = tracking_info['info']
                
                if container.status == 'running':
                    stats = await self._get_container_stats(container_id)
                    if stats:
                        event_data = EventData(
                            event_type=EventType.CONTAINER_STATS,
                            severity=EventSeverity.INFO,
                            source="container_collector",
                            data={
                                'container_id': container_id,
                                'container_name': container.name,
                                'stats': stats,
                                'runtime': self.container_runtime
                            }
                        )
                        
                        await self._send_event(event_data)
        
        except Exception as e:
            self.logger.error(f"❌ Container stats collection failed: {e}")
    
    async def _get_container_stats(self, container_id: str) -> Optional[Dict]:
        """Get container statistics"""
        try:
            if self.docker_available:
                result = subprocess.run(
                    ['docker', 'stats', '--no-stream', '--format', 'json', container_id],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    return json.loads(result.stdout.strip())
            
            elif self.podman_available:
                result = subprocess.run(
                    ['podman', 'stats', '--no-stream', '--format', 'json', container_id],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    return json.loads(result.stdout.strip())
        
        except Exception as e:
            self.logger.debug(f"Failed to get stats for container {container_id}: {e}")
        
        return None
    
    async def _perform_security_scan(self):
        """Perform security scanning on containers"""
        try:
            for container_id, tracking_info in self.known_containers.items():
                container = tracking_info['info']
                
                # Check for security issues
                security_issues = await self._check_container_security(container)
                
                for issue in security_issues:
                    await self._report_security_event(
                        container_id=container_id,
                        event_type=issue['type'],
                        severity=issue['severity'],
                        details=issue['details']
                    )
        
        except Exception as e:
            self.logger.error(f"❌ Security scanning failed: {e}")
    
    async def _check_container_security(self, container: ContainerInfo) -> List[Dict]:
        """Check container for security issues"""
        issues = []
        
        try:
            # Check for privileged mode
            if container.privileged:
                issues.append({
                    'type': 'privileged_container',
                    'severity': EventSeverity.HIGH,
                    'details': {
                        'container_name': container.name,
                        'risk': 'Container has full host access'
                    }
                })
            
            # Check for dangerous capabilities
            dangerous_caps = ['SYS_ADMIN', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE']
            for cap in dangerous_caps:
                if cap in container.capabilities:
                    issues.append({
                        'type': 'dangerous_capability',
                        'severity': EventSeverity.MEDIUM,
                        'details': {
                            'container_name': container.name,
                            'capability': cap,
                            'risk': f'Container has {cap} capability'
                        }
                    })
            
            # Check for root user
            if container.user == 'root' or container.user == '0':
                issues.append({
                    'type': 'root_container',
                    'severity': EventSeverity.MEDIUM,
                    'details': {
                        'container_name': container.name,
                        'user': container.user,
                        'risk': 'Container running as root'
                    }
                })
            
            # Check for suspicious security options
            suspicious_opts = ['no-new-privileges:false', 'seccomp:unconfined']
            for opt in suspicious_opts:
                if opt in container.security_opts:
                    issues.append({
                        'type': 'suspicious_security_opt',
                        'severity': EventSeverity.MEDIUM,
                        'details': {
                            'container_name': container.name,
                            'option': opt,
                            'risk': f'Suspicious security option: {opt}'
                        }
                    })
        
        except Exception as e:
            self.logger.error(f"❌ Container security check failed: {e}")
        
        return issues
    
    async def _find_privileged_containers(self) -> List[ContainerInfo]:
        """Find privileged containers"""
        privileged = []
        
        try:
            containers = await self._get_all_containers()
            
            for container in containers:
                if container.privileged:
                    privileged.append(container)
        
        except Exception as e:
            self.logger.error(f"❌ Privileged container search failed: {e}")
        
        return privileged
    
    async def _find_suspicious_containers(self) -> List[ContainerInfo]:
        """Find suspicious containers"""
        suspicious = []
        
        try:
            containers = await self._get_all_containers()
            
            for container in containers:
                # Check for suspicious patterns
                if (container.user == 'root' or 
                    any(cap in container.capabilities for cap in ['SYS_ADMIN', 'SYS_MODULE']) or
                    any(opt in container.security_opts for opt in ['no-new-privileges:false', 'seccomp:unconfined'])):
                    suspicious.append(container)
        
        except Exception as e:
            self.logger.error(f"❌ Suspicious container search failed: {e}")
        
        return suspicious
    
    async def _report_security_event(self, container_id: str, event_type: str, severity: EventSeverity, details: Dict):
        """Report security event"""
        try:
            event_data = EventData(
                event_type=EventType.CONTAINER_SECURITY,
                severity=severity,
                source="container_collector",
                data={
                    'container_id': container_id,
                    'security_event_type': event_type,
                    'details': details,
                    'runtime': self.container_runtime
                }
            )
            
            await self._send_event(event_data)
            
            # Track in container info
            if container_id in self.known_containers:
                self.known_containers[container_id]['security_events'].append({
                    'timestamp': datetime.now(),
                    'event_type': event_type,
                    'severity': severity,
                    'details': details
                })
        
        except Exception as e:
            self.logger.error(f"❌ Security event reporting failed: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get collector status"""
        return {
            'collector_type': 'container',
            'is_running': self.is_running,
            'container_runtime': self.container_runtime,
            'docker_available': self.docker_available,
            'podman_available': self.podman_available,
            'containers_tracked': len(self.known_containers),
            'security_events': len(self.security_events),
            'privileged_containers': len(self.privileged_containers),
            'suspicious_containers': len(self.suspicious_containers)
        }
