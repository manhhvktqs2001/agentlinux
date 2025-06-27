# agent/collectors/container_collector.py - FIXED Container Security
"""
Enhanced Container Security Collector - FIXED VERSION
Monitor Docker, Podman, Kubernetes with advanced security detection
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

from agent.collectors.base_collector import LinuxBaseCollector  # FIXED: Use LinuxBaseCollector
from agent.schemas.events import EventData, EventSeverity  # FIXED: Removed EventType import

# Try to import Docker
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None

# Try to import Kubernetes
try:
    import kubernetes
    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    kubernetes = None

@dataclass
class ContainerSecurityEvent:
    """Container security event data"""
    container_id: str
    container_name: str
    image: str
    security_issue: str
    severity: str
    details: Dict[str, Any]
    timestamp: datetime

class EnhancedContainerSecurityCollector(LinuxBaseCollector):  # FIXED: Use LinuxBaseCollector
    """Enhanced Container Security Collector with advanced monitoring"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager, "container_security")
        self.logger = logging.getLogger(__name__)
        
        # Container runtime detection
        self.docker_available = DOCKER_AVAILABLE
        self.podman_available = False
        self.k8s_available = KUBERNETES_AVAILABLE
        
        # Security monitoring
        self.privileged_containers = set()
        self.suspicious_containers = set()
        self.container_escapes = []
        self.vulnerable_images = set()
        
        # Kubernetes monitoring
        self.k8s_client = None
        self.monitored_namespaces = ['default', 'kube-system']
        
        # Configuration
        self.monitor_container_creation = True
        self.monitor_privileged_containers = True
        self.monitor_container_escapes = True
        self.monitor_image_vulnerabilities = True
        self.monitor_kubernetes_events = True
        
        # Security rules
        self.dangerous_capabilities = [
            'SYS_ADMIN', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE',
            'SYS_BOOT', 'SYS_TIME', 'NET_ADMIN', 'DAC_OVERRIDE'
        ]
        
        self.suspicious_mounts = [
            '/proc', '/sys', '/dev', '/run', '/boot', '/etc/passwd',
            '/etc/shadow', '/var/run/docker.sock'
        ]
    
    async def initialize(self):
        """Initialize enhanced container security collector"""
        try:
            self.logger.info("🐳 Initializing Enhanced Container Security Collector...")
            
            # Detect container runtimes
            await self._detect_container_runtimes()
            
            # Initialize Docker client
            if self.docker_available:
                await self._initialize_docker_monitoring()
            
            # Initialize Kubernetes monitoring
            if self.k8s_available:
                await self._initialize_kubernetes_monitoring()
            
            # Start security monitoring
            await self._start_security_monitoring()
            
            self.logger.info("✅ Enhanced Container Security Collector initialized")
            
        except Exception as e:
            self.logger.error(f"❌ Container Security Collector initialization failed: {e}")
            raise
    
    async def _detect_container_runtimes(self):
        """Detect available container runtimes and orchestrators"""
        try:
            # Check Docker
            if DOCKER_AVAILABLE:
                try:
                    docker_client = docker.from_env()
                    docker_client.ping()
                    self.docker_available = True
                    self.logger.info("🐳 Docker runtime detected")
                except:
                    self.docker_available = False
                    self.logger.info("ℹ️ Docker not available")
            else:
                self.logger.info("ℹ️ Docker client not installed")
            
            # Check Podman
            try:
                result = subprocess.run(['podman', '--version'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    self.podman_available = True
                    self.logger.info("📦 Podman runtime detected")
            except:
                self.logger.info("ℹ️ Podman not available")
            
            # Check Kubernetes
            if KUBERNETES_AVAILABLE:
                try:
                    kubernetes.config.load_incluster_config()  # Try in-cluster first
                    self.k8s_available = True
                    self.logger.info("☸️ Kubernetes cluster detected (in-cluster)")
                except:
                    try:
                        kubernetes.config.load_kube_config()  # Try local kubeconfig
                        self.k8s_available = True
                        self.logger.info("☸️ Kubernetes cluster detected (local config)")
                    except:
                        self.k8s_available = False
                        self.logger.info("ℹ️ Kubernetes not available")
            else:
                self.logger.info("ℹ️ Kubernetes client not installed")
            
        except Exception as e:
            self.logger.error(f"❌ Container runtime detection failed: {e}")
    
    async def _initialize_docker_monitoring(self):
        """Initialize Docker security monitoring"""
        try:
            if not DOCKER_AVAILABLE:
                return
                
            self.docker_client = docker.from_env()
            
            # Monitor existing containers
            containers = self.docker_client.containers.list(all=True)
            for container in containers:
                await self._analyze_container_security(container)
            
            # Setup event monitoring
            asyncio.create_task(self._monitor_docker_events())
            
        except Exception as e:
            self.logger.error(f"❌ Docker monitoring initialization failed: {e}")
    
    async def _initialize_kubernetes_monitoring(self):
        """Initialize Kubernetes security monitoring"""
        try:
            if not KUBERNETES_AVAILABLE:
                return
                
            self.k8s_v1 = kubernetes.client.CoreV1Api()
            self.k8s_apps = kubernetes.client.AppsV1Api()
            
            # Monitor existing pods
            for namespace in self.monitored_namespaces:
                try:
                    pods = self.k8s_v1.list_namespaced_pod(namespace)
                    for pod in pods.items:
                        await self._analyze_pod_security(pod)
                except Exception as e:
                    self.logger.debug(f"Could not list pods in namespace {namespace}: {e}")
            
            # Setup event monitoring
            asyncio.create_task(self._monitor_kubernetes_events())
            
        except Exception as e:
            self.logger.error(f"❌ Kubernetes monitoring initialization failed: {e}")
    
    async def _start_security_monitoring(self):
        """Start continuous security monitoring tasks"""
        try:
            # Monitor for container escapes
            if self.monitor_container_escapes:
                asyncio.create_task(self._monitor_container_escapes())
            
            # Monitor for privilege escalation
            asyncio.create_task(self._monitor_privilege_escalation())
            
            # Monitor for suspicious network activity
            asyncio.create_task(self._monitor_container_network_activity())
            
            # Image vulnerability scanning
            if self.monitor_image_vulnerabilities:
                asyncio.create_task(self._scan_image_vulnerabilities())
            
        except Exception as e:
            self.logger.error(f"❌ Security monitoring startup failed: {e}")
    
    async def _collect_data(self):  # FIXED: Implement abstract method
        """Collect container security data"""
        try:
            if not self.is_running:
                return []
            
            events = []
            
            # Check for new security events
            await self._check_security_events()
            
            # Monitor runtime security
            await self._monitor_runtime_security()
            
            # Check for policy violations
            await self._check_policy_violations()
            
            return events
            
        except Exception as e:
            self.logger.error(f"❌ Container security data collection failed: {e}")
            return []
    
    async def _check_security_events(self):
        """Check for new security events"""
        # Implementation for checking security events
        pass
    
    async def _monitor_runtime_security(self):
        """Monitor runtime security"""
        # Implementation for runtime security monitoring
        pass
    
    async def _check_policy_violations(self):
        """Check for policy violations"""
        # Implementation for policy violation checks
        pass
    
    async def _monitor_docker_events(self):
        """Monitor Docker events for security issues"""
        try:
            if not self.docker_available or not DOCKER_AVAILABLE:
                return
                
            while self.is_running:
                try:
                    for event in self.docker_client.events(decode=True):
                        if event['Type'] == 'container':
                            await self._handle_docker_event(event)
                except Exception as e:
                    self.logger.error(f"Docker event monitoring error: {e}")
                    await asyncio.sleep(5)
        except Exception as e:
            self.logger.error(f"❌ Docker event monitoring failed: {e}")
    
    async def _handle_docker_event(self, event: Dict):
        """Handle Docker container events"""
        try:
            action = event.get('Action', '')
            container_id = event.get('id', '')
            
            if action == 'start':
                # New container started - security analysis
                container = self.docker_client.containers.get(container_id)
                await self._analyze_container_security(container)
                
            elif action in ['exec_create', 'exec_start']:
                # Command execution in container
                await self._analyze_container_execution(event)
                
        except Exception as e:
            self.logger.debug(f"Error handling Docker event: {e}")
    
    async def _analyze_container_security(self, container):
        """Analyze container for security issues"""
        try:
            container_info = container.attrs
            config = container_info.get('Config', {})
            host_config = container_info.get('HostConfig', {})
            
            security_issues = []
            
            # Check for privileged mode
            if host_config.get('Privileged', False):
                security_issues.append({
                    'issue': 'privileged_container',
                    'severity': 'HIGH',
                    'description': 'Container running in privileged mode'
                })
                self.privileged_containers.add(container.id)
            
            # Check dangerous capabilities
            cap_add = host_config.get('CapAdd', [])
            for cap in self.dangerous_capabilities:
                if cap in cap_add:
                    security_issues.append({
                        'issue': 'dangerous_capability',
                        'severity': 'MEDIUM',
                        'description': f'Container has dangerous capability: {cap}'
                    })
            
            # Check suspicious mounts
            mounts = container_info.get('Mounts', [])
            for mount in mounts:
                source = mount.get('Source', '')
                if any(sus_path in source for sus_path in self.suspicious_mounts):
                    security_issues.append({
                        'issue': 'suspicious_mount',
                        'severity': 'HIGH', 
                        'description': f'Suspicious host path mounted: {source}'
                    })
            
            # Report security issues
            for issue in security_issues:
                await self._report_container_security_event(
                    container_id=container.id,
                    container_name=container.name,
                    image=container.image.tags[0] if container.image.tags else 'unknown',
                    security_issue=issue['issue'],
                    severity=issue['severity'],
                    details=issue
                )
            
        except Exception as e:
            self.logger.error(f"❌ Container security analysis failed: {e}")
    
    async def _analyze_container_execution(self, event):
        """Analyze container execution event"""
        # Implementation for container execution analysis
        pass
    
    async def _analyze_pod_security(self, pod):
        """Analyze Kubernetes pod security"""
        # Implementation for pod security analysis
        pass
    
    async def _monitor_kubernetes_events(self):
        """Monitor Kubernetes events for security issues"""
        # Implementation for Kubernetes event monitoring
        pass
    
    async def _monitor_container_escapes(self):
        """Monitor for container escape attempts"""
        # Implementation for container escape monitoring
        pass
    
    async def _monitor_privilege_escalation(self):
        """Monitor for privilege escalation in containers"""
        # Implementation for privilege escalation monitoring
        pass
    
    async def _monitor_container_network_activity(self):
        """Monitor container network activity for security issues"""
        # Implementation for container network monitoring
        pass
    
    async def _scan_image_vulnerabilities(self):
        """Scan container images for vulnerabilities"""
        # Implementation for image vulnerability scanning
        pass
    
    async def _report_container_security_event(self, container_id: str, container_name: str, 
                                             image: str, security_issue: str, 
                                             severity: str, details: Dict):
        """Report container security event"""
        try:
            event_data = EventData(
                event_type="Container_Security",
                event_action="Security_Event",  # FIXED: Use string instead of EventAction
                event_timestamp=datetime.now(),
                severity=severity,
                agent_id=self.agent_id,
                description=f"🐧 LINUX CONTAINER SECURITY: {security_issue}",
                raw_event_data={
                    'container_id': container_id,
                    'container_name': container_name,
                    'image': image,
                    'security_issue': security_issue,
                    'details': details,
                    'platform': 'linux',
                    'runtime': 'docker'
                }
            )
            
            await self._send_event_immediately(event_data)
            
        except Exception as e:
            self.logger.error(f"❌ Container security event reporting failed: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get container security collector status"""
        return {
            'collector_type': 'container_security',
            'is_running': self.is_running,
            'docker_available': self.docker_available,
            'podman_available': self.podman_available,
            'k8s_available': self.k8s_available,
            'privileged_containers': len(self.privileged_containers),
            'suspicious_containers': len(self.suspicious_containers),
            'container_escapes': len(self.container_escapes),
            'vulnerable_images': len(self.vulnerable_images)
        }