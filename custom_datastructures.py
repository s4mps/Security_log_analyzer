#!/usr/bin/env python3
"""
Custom Data Structures for Security Log Analyzer
Implements user-defined data structures as per requirements
"""

class CircularBuffer:
    def __init__(self, size):
        self.buffer = [None] * size
        self.size = size
        self.head = 0
        self.tail = 0
        self.count = 0
    
    def add(self, item):
        """Add item to buffer, overwriting oldest if full"""
        self.buffer[self.head] = item
        self.head = (self.head + 1) % self.size
        
        if self.count < self.size:
            self.count += 1
        else:
            self.tail = (self.tail + 1) % self.size
    
    def get_items(self):
        """Get all items in correct order (oldest to newest)"""
        if self.count == 0:
            return []
        
        items = []
        for i in range(self.count):
            index = (self.tail + i) % self.size
            items.append(self.buffer[index])
        
        return items
    
    def clear(self):
        """Clear all items from buffer"""
        self.head = 0
        self.tail = 0
        self.count = 0
    
    def __len__(self):
        return self.count
    
    def __str__(self):
        return f"CircularBuffer(size={self.size}, items={self.count})"


class AttackCounter:
    """Custom data structure to track attack attempts"""
    
    def __init__(self):
        self.attempts = {}  # key -> list of timestamps
        self.windows = {}   # key -> CircularBuffer
    
    def add_attempt(self, key, timestamp, window_size=5):
        """Add attempt for a key (IP/user)"""
        if key not in self.attempts:
            self.attempts[key] = []
            self.windows[key] = CircularBuffer(window_size)
        
        self.attempts[key].append(timestamp)
        self.windows[key].add(timestamp)
    
    def get_recent_attempts(self, key, window_seconds=30):
        """Get attempts within time window using custom buffer"""
        if key not in self.windows:
            return []
        
        from datetime import datetime, timedelta
        recent_items = self.windows[key].get_items()
        
        # Filter by time window
        if not recent_items:
            return []
        
        cutoff_time = recent_items[-1] - timedelta(seconds=window_seconds)
        return [ts for ts in recent_items if ts >= cutoff_time]
    
    def has_brute_force(self, key, min_attempts=3, window_seconds=30):
        """Check if key has brute force pattern using custom buffer"""
        recent = self.get_recent_attempts(key, window_seconds)
        return len(recent) >= min_attempts
    
    def get_all_keys(self):
        """Get all tracked keys"""
        return list(self.attempts.keys())
    
    def reset_key(self, key):
        """Reset tracking for a specific key"""
        if key in self.attempts:
            del self.attempts[key]
        if key in self.windows:
            del self.windows[key]