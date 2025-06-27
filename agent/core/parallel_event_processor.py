# agent/core/parallel_event_processor.py - Compatibility File
"""
Parallel Event Processor - Compatibility Import
This file provides backward compatibility for imports
"""

# Import the actual implementation from event_processor.py
from agent.core.event_processor import EventProcessor as ParallelEventProcessor

# Re-export for compatibility
__all__ = ['ParallelEventProcessor']