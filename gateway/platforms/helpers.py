"""Helper utilities for platform adapters.

This module provides shared utilities used across different platform adapters.
"""


class ThreadParticipationTracker:
    """Track thread participation for mention gating.
    
    Simple stub implementation for testing purposes.
    """
    
    def __init__(self, platform_name: str):
        """Initialize the tracker.
        
        Args:
            platform_name: Name of the platform (e.g., "matrix")
        """
        self.platform_name = platform_name
        self._tracked_threads = set()
    
    def mark(self, thread_id: str) -> None:
        """Mark a thread as participated in.
        
        Args:
            thread_id: Thread ID to mark
        """
        if thread_id:
            self._tracked_threads.add(thread_id)
    
    def is_participating(self, thread_id: str) -> bool:
        """Check if we've participated in a thread.
        
        Args:
            thread_id: Thread ID to check
            
        Returns:
            True if we've participated in this thread
        """
        return thread_id in self._tracked_threads
