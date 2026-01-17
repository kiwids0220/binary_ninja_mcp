"""
TTD (Time Travel Debugging) operations for Binary Ninja MCP.

This module provides access to TTD functionality when using the DBGENG_TTD
debug adapter. It allows querying TTD.Calls(), TTD.Memory, and other
TTD Data Model features.
"""

import binaryninja as bn
from typing import Dict, Any, List, Optional
from .binary_operations import BinaryOperations


class TTDOperations:
    """Operations for TTD (Time Travel Debugging) analysis."""
    
    def __init__(self, binary_ops: BinaryOperations):
        self.binary_ops = binary_ops
    
    def _get_debugger_controller(self):
        """Get the DebuggerController for the current view."""
        bv = self.binary_ops.current_view
        if not bv:
            return None
        
        try:
            # Import debugger module
            from binaryninja.debugger import DebuggerController
            controller = DebuggerController.get_controller(bv)
            return controller
        except ImportError:
            bn.log_error("Debugger module not available")
            return None
        except Exception as e:
            bn.log_error(f"Failed to get debugger controller: {e}")
            return None
    
    def is_ttd_available(self) -> Dict[str, Any]:
        """Check if TTD is available in the current debugging session."""
        controller = self._get_debugger_controller()
        if not controller:
            return {
                "available": False,
                "error": "No debugger controller available"
            }
        
        try:
            is_ttd = controller.is_ttd
            is_connected = controller.is_connected
            
            return {
                "available": is_ttd,
                "connected": is_connected,
                "adapter_type": str(controller.adapter_type) if hasattr(controller, 'adapter_type') else None
            }
        except Exception as e:
            return {
                "available": False,
                "error": str(e)
            }
    
    def get_ttd_calls_for_symbols(
        self,
        symbols: str,
        start_return_address: int = 0,
        end_return_address: int = 0
    ) -> Dict[str, Any]:
        """
        Query TTD.Calls() for function call events.
        
        This is equivalent to the WinDbg command:
            dx @$cursession.TTD.Calls("module!function")
        
        Args:
            symbols: Comma-separated list of symbols (e.g., "kernel32!CreateFileW, ntdll!NtCreateFile")
            start_return_address: Optional filter - only include calls with return address >= this value
            end_return_address: Optional filter - only include calls with return address < this value
        
        Returns:
            Dictionary containing:
            - status: "success" or "error"
            - count: Number of call events found
            - events: List of call event dictionaries
        """
        controller = self._get_debugger_controller()
        if not controller:
            return {"status": "error", "error": "No debugger controller available"}
        
        if not controller.is_connected:
            return {"status": "error", "error": "Debugger not connected"}
        
        if not controller.is_ttd:
            return {"status": "error", "error": "TTD not available - ensure you're debugging a TTD trace"}
        
        try:
            # Call the TTD API
            call_events = controller.get_ttd_calls_for_symbols(
                symbols, 
                start_return_address, 
                end_return_address
            )
            
            # Convert events to dictionaries
            events_list = []
            for event in call_events:
                event_dict = {
                    "event_type": event.event_type,
                    "thread_id": event.thread_id,
                    "unique_thread_id": event.unique_thread_id,
                    "function": event.function,
                    "function_address": hex(event.function_address),
                    "return_address": hex(event.return_address),
                    "has_return_value": event.has_return_value,
                    "parameters": list(event.parameters) if hasattr(event, 'parameters') else [],
                    "time_start": {
                        "sequence": hex(event.time_start.sequence),
                        "step": hex(event.time_start.step),
                        "string": f"{event.time_start.sequence:x}:{event.time_start.step:x}"
                    },
                    "time_end": {
                        "sequence": hex(event.time_end.sequence),
                        "step": hex(event.time_end.step),
                        "string": f"{event.time_end.sequence:x}:{event.time_end.step:x}"
                    }
                }
                
                if event.has_return_value:
                    event_dict["return_value"] = hex(event.return_value)
                
                events_list.append(event_dict)
            
            return {
                "status": "success",
                "count": len(events_list),
                "symbols": symbols,
                "events": events_list
            }
            
        except Exception as e:
            bn.log_error(f"Failed to query TTD calls: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_ttd_memory_access(
        self,
        address: int,
        size: int,
        access_type: str = "rwe"
    ) -> Dict[str, Any]:
        """
        Query TTD memory access events for a specific address range.
        
        Args:
            address: Starting memory address to query
            size: Size of memory region to query
            access_type: Type of access - "r" (read), "w" (write), "e" (execute), or combinations like "rw", "rwe"
        
        Returns:
            Dictionary containing memory access events
        """
        controller = self._get_debugger_controller()
        if not controller:
            return {"status": "error", "error": "No debugger controller available"}
        
        if not controller.is_connected:
            return {"status": "error", "error": "Debugger not connected"}
        
        if not controller.is_ttd:
            return {"status": "error", "error": "TTD not available"}
        
        try:
            # Call the TTD API
            memory_events = controller.get_ttd_memory_access_for_address(address, size, access_type)
            
            # Convert events to dictionaries
            events_list = []
            for event in memory_events:
                event_dict = {
                    "event_type": event.event_type,
                    "thread_id": event.thread_id,
                    "unique_thread_id": event.unique_thread_id,
                    "address": hex(event.address),
                    "memory_address": hex(event.memory_address) if hasattr(event, 'memory_address') else hex(event.address),
                    "size": event.size,
                    "instruction_address": hex(event.instruction_address) if hasattr(event, 'instruction_address') else None,
                    "value": hex(event.value) if hasattr(event, 'value') else None,
                    "access_type": str(event.access_type) if hasattr(event, 'access_type') else access_type,
                    "time_start": {
                        "sequence": hex(event.time_start.sequence),
                        "step": hex(event.time_start.step),
                        "string": f"{event.time_start.sequence:x}:{event.time_start.step:x}"
                    },
                    "time_end": {
                        "sequence": hex(event.time_end.sequence),
                        "step": hex(event.time_end.step),
                        "string": f"{event.time_end.sequence:x}:{event.time_end.step:x}"
                    }
                }
                events_list.append(event_dict)
            
            return {
                "status": "success",
                "count": len(events_list),
                "address": hex(address),
                "size": size,
                "access_type": access_type,
                "events": events_list
            }
            
        except Exception as e:
            bn.log_error(f"Failed to query TTD memory access: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_ttd_events(self, event_type: str) -> Dict[str, Any]:
        """
        Get TTD events of a specific type.
        
        Args:
            event_type: Type of event - "thread_created", "thread_terminated", 
                       "module_loaded", "module_unloaded", "exception", or "all"
        
        Returns:
            Dictionary containing events of the specified type
        """
        controller = self._get_debugger_controller()
        if not controller:
            return {"status": "error", "error": "No debugger controller available"}
        
        if not controller.is_connected:
            return {"status": "error", "error": "Debugger not connected"}
        
        if not controller.is_ttd:
            return {"status": "error", "error": "TTD not available"}
        
        try:
            # Import TTD event types
            from binaryninja.debugger import TTDEventType
            
            # Map string to event type
            type_map = {
                "thread_created": TTDEventType.ThreadCreated,
                "thread_terminated": TTDEventType.ThreadTerminated,
                "module_loaded": TTDEventType.ModuleLoaded,
                "module_unloaded": TTDEventType.ModuleUnloaded,
                "exception": TTDEventType.Exception,
            }
            
            if event_type.lower() == "all":
                # Get all event types
                all_events = []
                for etype in type_map.values():
                    events = controller.get_ttd_events(etype)
                    all_events.extend(events)
                ttd_events = all_events
            else:
                etype = type_map.get(event_type.lower())
                if etype is None:
                    return {
                        "status": "error", 
                        "error": f"Unknown event type: {event_type}. Valid types: {list(type_map.keys()) + ['all']}"
                    }
                ttd_events = controller.get_ttd_events(etype)
            
            # Convert events to dictionaries
            events_list = []
            for event in ttd_events:
                event_dict = {
                    "type": str(event.type) if hasattr(event, 'type') else event_type,
                    "position": {
                        "sequence": hex(event.position.sequence),
                        "step": hex(event.position.step),
                        "string": f"{event.position.sequence:x}:{event.position.step:x}"
                    }
                }
                
                # Add module info if present
                if hasattr(event, 'module') and event.module:
                    event_dict["module"] = {
                        "name": event.module.name,
                        "address": hex(event.module.address),
                        "size": event.module.size,
                        "checksum": event.module.checksum if hasattr(event.module, 'checksum') else None,
                        "timestamp": event.module.timestamp if hasattr(event.module, 'timestamp') else None
                    }
                
                # Add thread info if present
                if hasattr(event, 'thread') and event.thread:
                    event_dict["thread"] = {
                        "unique_id": event.thread.unique_id,
                        "id": event.thread.id,
                        "lifetime_start": f"{event.thread.lifetime_start.sequence:x}:{event.thread.lifetime_start.step:x}" if hasattr(event.thread, 'lifetime_start') else None,
                        "lifetime_end": f"{event.thread.lifetime_end.sequence:x}:{event.thread.lifetime_end.step:x}" if hasattr(event.thread, 'lifetime_end') else None,
                    }
                
                # Add exception info if present
                if hasattr(event, 'exception') and event.exception:
                    event_dict["exception"] = {
                        "type": str(event.exception.type) if hasattr(event.exception, 'type') else None,
                        "program_counter": hex(event.exception.program_counter) if hasattr(event.exception, 'program_counter') else None,
                        "code": hex(event.exception.code) if hasattr(event.exception, 'code') else None,
                        "flags": event.exception.flags if hasattr(event.exception, 'flags') else None,
                        "record_address": hex(event.exception.record_address) if hasattr(event.exception, 'record_address') else None
                    }
                
                events_list.append(event_dict)
            
            return {
                "status": "success",
                "count": len(events_list),
                "event_type": event_type,
                "events": events_list
            }
            
        except Exception as e:
            bn.log_error(f"Failed to query TTD events: {e}")
            return {"status": "error", "error": str(e)}
    
    def get_current_ttd_position(self) -> Dict[str, Any]:
        """Get the current position in the TTD trace."""
        controller = self._get_debugger_controller()
        if not controller:
            return {"status": "error", "error": "No debugger controller available"}
        
        if not controller.is_ttd:
            return {"status": "error", "error": "TTD not available"}
        
        try:
            position = controller.get_current_ttd_position()
            return {
                "status": "success",
                "position": {
                    "sequence": hex(position.sequence),
                    "step": hex(position.step),
                    "string": f"{position.sequence:x}:{position.step:x}"
                }
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def set_ttd_position(self, position_str: str) -> Dict[str, Any]:
        """
        Navigate to a specific position in the TTD trace.
        
        Args:
            position_str: Position in "sequence:step" hex format (e.g., "1234:5678")
        
        Returns:
            Dictionary with success/error status
        """
        controller = self._get_debugger_controller()
        if not controller:
            return {"status": "error", "error": "No debugger controller available"}
        
        if not controller.is_ttd:
            return {"status": "error", "error": "TTD not available"}
        
        try:
            # Parse position string
            parts = position_str.split(":")
            if len(parts) != 2:
                return {"status": "error", "error": f"Invalid position format: {position_str}. Use 'sequence:step' format."}
            
            sequence = int(parts[0], 16)
            step = int(parts[1], 16)
            
            # Create TTDPosition object
            from binaryninja.debugger import TTDPosition
            position = TTDPosition(sequence, step)
            
            # Navigate to position
            success = controller.set_ttd_position(position)
            
            if success:
                return {
                    "status": "success",
                    "position": {
                        "sequence": hex(sequence),
                        "step": hex(step),
                        "string": position_str
                    }
                }
            else:
                return {"status": "error", "error": "Failed to navigate to position"}
            
        except ValueError as e:
            return {"status": "error", "error": f"Invalid position format: {e}"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
