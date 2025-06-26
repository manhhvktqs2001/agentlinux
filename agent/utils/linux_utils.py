# agent/utils/linux_utils.py - Linux Utilities
"""
Linux Utilities - System information gathering and Linux-specific helper functions
Enhanced utilities for Linux EDR agent operations
"""

import os
import sys
import subprocess
import platform
import psutil
import pwd
import grp
import stat
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging

logger = logging.getLogger(__name__)

def is_root_user() -> bool:
    """Check if current user has root privileges"""
    return os.geteuid() == 0

def get_current_user_info() -> Dict[str, Any]:
    """Get current user information"""
    try:
        uid = os.getuid()
        euid = os.geteuid()
        
        current_user = pwd.getpwuid(uid)
        effective_user = pwd.getpwuid(euid)
        
        # Get user groups
        groups = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]
        
        return {
            'uid': uid,
            'euid': euid,
            'username': current_user.pw_name,
            'effective_username': effective_user.pw_name,
            'home_directory': current_user.pw_dir,
            'shell': current_user.pw_shell,
            'groups': groups,
            'is_root': is_root_user()
        }
    except Exception as e:
        logger.error(f"Failed to get user info: {e}")
        return {'error': str(e)}

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive Linux system information"""
    try:
        info = {
            'hostname': platform.node(),
            'kernel': platform.release(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'system': platform.system(),
            'distribution': 'Unknown',
            'distribution_version': 'Unknown',
            'distribution_id': 'Unknown'
        }
        
        # Get distribution information
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('NAME='):
                        info['distribution'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION='):
                        info['distribution_version'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('ID='):
                        info['distribution_id'] = line.split('=')[1].strip().strip('"')
                    elif line.startswith('VERSION_ID='):
                        info['version_id'] = line.split('=')[1].strip().strip('"')
        except Exception as e:
            logger.debug(f"Could not read /etc/os-release: {e}")
        
        # Get additional system info
        try:
            info['uptime'] = time.time() - psutil.boot_time()
            info['cpu_count'] = psutil.cpu_count()
            info['cpu_count_physical'] = psutil.cpu_count(logical=False)
            
            memory = psutil.virtual_memory()
            info['memory_total'] = memory.total
            info['memory_available'] = memory.available
            
            disk = psutil.disk_usage('/')
            info['disk_total'] = disk.total
            info['disk_free'] = disk.free
            
        except Exception as e:
            logger.debug(f"Error getting additional system info: {e}")
        
        return info
        
    except Exception as e:
        logger.error(f"Failed to get system info: {e}")
        return {'error': str(e)}

def get_network_interfaces() -> Dict[str, Dict[str, Any]]:
    """Get network interface information"""
    try:
        interfaces = {}
        
        # Get interface addresses
        net_if_addrs = psutil.net_if_addrs()
        
        for interface, addresses in net_if_addrs.items():
            interface_info = {
                'name': interface,
                'addresses': [],
                'up': False,
                'speed': None,
                'mtu': None
            }
            
            for addr in addresses:
                interface_info['addresses'].append({
                    'family': addr.family.name,
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
            
            interfaces[interface] = interface_info
        
        # Get interface status
        try:
            net_if_stats = psutil.net_if_stats()
            for interface, stats in net_if_stats.items():
                if interface in interfaces:
                    interfaces[interface]['up'] = stats.isup
                    interfaces[interface]['speed'] = stats.speed
                    interfaces[interface]['mtu'] = stats.mtu
        except Exception as e:
            logger.debug(f"Could not get interface stats: {e}")
        
        return interfaces
        
    except Exception as e:
        logger.error(f"Failed to get network interfaces: {e}")
        return {}

def get_mounted_filesystems() -> List[Dict[str, Any]]:
    """Get mounted filesystem information"""
    try:
        filesystems = []
        
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                filesystem_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent
                }
                filesystems.append(filesystem_info)
            except Exception as e:
                logger.debug(f"Could not get usage for {partition.mountpoint}: {e}")
        
        return filesystems
        
    except Exception as e:
        logger.error(f"Failed to get mounted filesystems: {e}")
        return []

def get_running_services() -> List[Dict[str, Any]]:
    """Get running system services"""
    try:
        services = []
        
        # Check if systemd is available
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            service_info = {
                                'name': parts[0],
                                'load': parts[1],
                                'active': parts[2],
                                'sub': parts[3],
                                'description': ' '.join(parts[4:]) if len(parts) > 4 else ''
                            }
                            services.append(service_info)
        except Exception as e:
            logger.debug(f"Could not get systemd services: {e}")
        
        return services
        
    except Exception as e:
        logger.error(f"Failed to get running services: {e}")
        return []

def get_open_ports() -> List[Dict[str, Any]]:
    """Get open network ports"""
    try:
        ports = []
        
        for conn in psutil.net_connections():
            if conn.status == 'LISTEN':
                port_info = {
                    'port': conn.laddr.port,
                    'address': conn.laddr.ip,
                    'protocol': 'tcp' if conn.type == socket.SOCK_STREAM else 'udp',
                    'pid': conn.pid,
                    'status': conn.status
                }
                ports.append(port_info)
        
        return ports
        
    except Exception as e:
        logger.error(f"Failed to get open ports: {e}")
        return []

def check_file_permissions(file_path: str) -> Dict[str, Any]:
    """Check file permissions and ownership"""
    try:
        stat_info = os.stat(file_path)
        
        # Get file mode
        mode = stat_info.st_mode
        permissions = {
            'readable': bool(mode & stat.S_IRUSR),
            'writable': bool(mode & stat.S_IWUSR),
            'executable': bool(mode & stat.S_IXUSR),
            'mode': oct(mode)[-3:],  # Octal representation
            'owner_read': bool(mode & stat.S_IRUSR),
            'owner_write': bool(mode & stat.S_IWUSR),
            'owner_exec': bool(mode & stat.S_IXUSR),
            'group_read': bool(mode & stat.S_IRGRP),
            'group_write': bool(mode & stat.S_IWGRP),
            'group_exec': bool(mode & stat.S_IXGRP),
            'other_read': bool(mode & stat.S_IROTH),
            'other_write': bool(mode & stat.S_IWOTH),
            'other_exec': bool(mode & stat.S_IXOTH)
        }
        
        # Get ownership
        try:
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
        except:
            owner = str(stat_info.st_uid)
        
        try:
            group = grp.getgrgid(stat_info.st_gid).gr_name
        except:
            group = str(stat_info.st_gid)
        
        return {
            'path': file_path,
            'exists': True,
            'permissions': permissions,
            'owner': owner,
            'group': group,
            'uid': stat_info.st_uid,
            'gid': stat_info.st_gid,
            'size': stat_info.st_size,
            'modified': stat_info.st_mtime,
            'accessed': stat_info.st_atime
        }
        
    except FileNotFoundError:
        return {
            'path': file_path,
            'exists': False,
            'error': 'File not found'
        }
    except Exception as e:
        return {
            'path': file_path,
            'exists': False,
            'error': str(e)
        }

def get_process_tree(pid: int) -> Dict[str, Any]:
    """Get process tree information"""
    try:
        process = psutil.Process(pid)
        
        # Get process info
        process_info = {
            'pid': process.pid,
            'ppid': process.ppid(),
            'name': process.name(),
            'exe': process.exe(),
            'cmdline': process.cmdline(),
            'cwd': process.cwd(),
            'username': process.username(),
            'status': process.status(),
            'create_time': process.create_time(),
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'memory_info': process.memory_info()._asdict(),
            'num_threads': process.num_threads(),
            'connections': []
        }
        
        # Get network connections
        try:
            connections = process.connections()
            for conn in connections:
                conn_info = {
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                }
                process_info['connections'].append(conn_info)
        except Exception as e:
            logger.debug(f"Could not get connections for PID {pid}: {e}")
        
        # Get children
        try:
            children = process.children(recursive=True)
            process_info['children'] = [child.pid for child in children]
        except Exception as e:
            logger.debug(f"Could not get children for PID {pid}: {e}")
            process_info['children'] = []
        
        return process_info
        
    except psutil.NoSuchProcess:
        return {'error': f'Process {pid} not found'}
    except Exception as e:
        return {'error': str(e)}

def get_system_load() -> Dict[str, float]:
    """Get system load average"""
    try:
        load_avg = os.getloadavg()
        return {
            '1min': load_avg[0],
            '5min': load_avg[1],
            '15min': load_avg[2]
        }
    except Exception as e:
        logger.error(f"Failed to get system load: {e}")
        return {'error': str(e)}

def get_memory_usage() -> Dict[str, Any]:
    """Get detailed memory usage information"""
    try:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'free': memory.free,
            'percent': memory.percent,
            'buffers': getattr(memory, 'buffers', 0),
            'cached': getattr(memory, 'cached', 0),
            'shared': getattr(memory, 'shared', 0),
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_free': swap.free,
            'swap_percent': swap.percent
        }
    except Exception as e:
        logger.error(f"Failed to get memory usage: {e}")
        return {'error': str(e)}

def get_disk_io_stats() -> Dict[str, Any]:
    """Get disk I/O statistics"""
    try:
        disk_io = psutil.disk_io_counters()
        
        return {
            'read_count': disk_io.read_count,
            'write_count': disk_io.write_count,
            'read_bytes': disk_io.read_bytes,
            'write_bytes': disk_io.write_bytes,
            'read_time': disk_io.read_time,
            'write_time': disk_io.write_time
        }
    except Exception as e:
        logger.error(f"Failed to get disk I/O stats: {e}")
        return {'error': str(e)}

def get_network_io_stats() -> Dict[str, Any]:
    """Get network I/O statistics"""
    try:
        net_io = psutil.net_io_counters()
        
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    except Exception as e:
        logger.error(f"Failed to get network I/O stats: {e}")
        return {'error': str(e)}

def check_security_modules() -> Dict[str, bool]:
    """Check for security modules (SELinux, AppArmor)"""
    try:
        security_modules = {
            'selinux': False,
            'apparmor': False,
            'capabilities': False
        }
        
        # Check SELinux
        if os.path.exists('/sys/fs/selinux'):
            security_modules['selinux'] = True
        
        # Check AppArmor
        if os.path.exists('/sys/kernel/security/apparmor'):
            security_modules['apparmor'] = True
        
        # Check Linux capabilities
        if os.path.exists('/proc/sys/kernel/cap_last_cap'):
            security_modules['capabilities'] = True
        
        return security_modules
        
    except Exception as e:
        logger.error(f"Failed to check security modules: {e}")
        return {'error': str(e)}

def get_kernel_modules() -> List[Dict[str, Any]]:
    """Get loaded kernel modules"""
    try:
        modules = []
        
        with open('/proc/modules', 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    module_info = {
                        'name': parts[0],
                        'size': int(parts[1]),
                        'refcount': int(parts[2]),
                        'dependencies': parts[3].split(',') if parts[3] != '-' else []
                    }
                    modules.append(module_info)
        
        return modules
        
    except Exception as e:
        logger.error(f"Failed to get kernel modules: {e}")
        return []

def get_system_uptime() -> Dict[str, Any]:
    """Get system uptime information"""
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.read().split()[0])
        
        days = int(uptime_seconds // 86400)
        hours = int((uptime_seconds % 86400) // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        
        return {
            'uptime_seconds': uptime_seconds,
            'uptime_days': days,
            'uptime_hours': hours,
            'uptime_minutes': minutes,
            'uptime_seconds_remainder': seconds,
            'formatted': f"{days}d {hours}h {minutes}m {seconds}s"
        }
    except Exception as e:
        logger.error(f"Failed to get system uptime: {e}")
        return {'error': str(e)}

def check_file_integrity(file_path: str) -> Dict[str, Any]:
    """Check file integrity (size, modification time, permissions)"""
    try:
        stat_info = os.stat(file_path)
        
        return {
            'path': file_path,
            'exists': True,
            'size': stat_info.st_size,
            'modified_time': stat_info.st_mtime,
            'access_time': stat_info.st_atime,
            'permissions': oct(stat_info.st_mode)[-3:],
            'owner': stat_info.st_uid,
            'group': stat_info.st_gid,
            'inode': stat_info.st_ino,
            'device': stat_info.st_dev
        }
    except FileNotFoundError:
        return {
            'path': file_path,
            'exists': False,
            'error': 'File not found'
        }
    except Exception as e:
        return {
            'path': file_path,
            'exists': False,
            'error': str(e)
        }

def get_environment_variables() -> Dict[str, str]:
    """Get environment variables (filtered for security)"""
    try:
        env_vars = {}
        sensitive_keys = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'AUTH']
        
        for key, value in os.environ.items():
            # Filter out sensitive environment variables
            if not any(sensitive in key.upper() for sensitive in sensitive_keys):
                env_vars[key] = value
        
        return env_vars
    except Exception as e:
        logger.error(f"Failed to get environment variables: {e}")
        return {'error': str(e)}

def check_system_health() -> Dict[str, Any]:
    """Perform basic system health check"""
    try:
        health_status = {
            'overall': 'healthy',
            'checks': {},
            'warnings': [],
            'errors': []
        }
        
        # Check CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        health_status['checks']['cpu'] = {
            'usage_percent': cpu_percent,
            'status': 'normal' if cpu_percent < 80 else 'high'
        }
        if cpu_percent > 90:
            health_status['warnings'].append(f"High CPU usage: {cpu_percent}%")
        
        # Check memory usage
        memory = psutil.virtual_memory()
        health_status['checks']['memory'] = {
            'usage_percent': memory.percent,
            'available_mb': memory.available / (1024 * 1024),
            'status': 'normal' if memory.percent < 80 else 'high'
        }
        if memory.percent > 90:
            health_status['warnings'].append(f"High memory usage: {memory.percent}%")
        
        # Check disk usage
        disk = psutil.disk_usage('/')
        health_status['checks']['disk'] = {
            'usage_percent': disk.percent,
            'free_gb': disk.free / (1024 * 1024 * 1024),
            'status': 'normal' if disk.percent < 80 else 'high'
        }
        if disk.percent > 90:
            health_status['warnings'].append(f"High disk usage: {disk.percent}%")
        
        # Check load average
        load_avg = os.getloadavg()
        health_status['checks']['load'] = {
            '1min': load_avg[0],
            '5min': load_avg[1],
            '15min': load_avg[2],
            'status': 'normal' if load_avg[0] < 5.0 else 'high'
        }
        if load_avg[0] > 10.0:
            health_status['warnings'].append(f"High system load: {load_avg[0]}")
        
        # Check for failed services
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=failed', '--no-pager', '--no-legend'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            failed_services = []
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        failed_services.append(line.split()[0])
            
            health_status['checks']['services'] = {
                'failed_count': len(failed_services),
                'failed_services': failed_services,
                'status': 'normal' if len(failed_services) == 0 else 'warning'
            }
            
            if failed_services:
                health_status['warnings'].append(f"Failed services: {', '.join(failed_services)}")
                
        except Exception as e:
            health_status['checks']['services'] = {
                'error': str(e),
                'status': 'error'
            }
        
        # Determine overall status
        if health_status['warnings']:
            health_status['overall'] = 'warning'
        if health_status['errors']:
            health_status['overall'] = 'error'
        
        return health_status
        
    except Exception as e:
        logger.error(f"Failed to check system health: {e}")
        return {
            'overall': 'error',
            'error': str(e)
        }
