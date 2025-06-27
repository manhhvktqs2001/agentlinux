# agent/core/parallel_collector_manager.py - Compatibility File
"""
Parallel Collector Manager - Compatibility Import
This file provides backward compatibility for imports
"""

# Import the actual implementation from collector_manager.py
from agent.core.collector_manager import LinuxCollectorManager as ParallelCollectorManager

# Re-export for compatibility
__all__ = ['ParallelCollectorManager']