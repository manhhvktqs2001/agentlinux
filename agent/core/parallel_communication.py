# agent/core/parallel_communication.py - Compatibility File
"""
Parallel Communication - Compatibility Import
This file provides backward compatibility for imports
"""

# Import the actual implementation from communication.py
from agent.core.communication import EnhancedParallelCommunication

# Re-export for compatibility
__all__ = ['EnhancedParallelCommunication']