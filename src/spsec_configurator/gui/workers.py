# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

"""Background worker threads for CAN ops: progress callbacks + cancellation."""

from __future__ import annotations

import threading
import queue
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional, Any, List
from abc import ABC, abstractmethod


class WorkerStatus(Enum):
    """Status of a worker thread"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


@dataclass
class WorkerResult:
    """Result from a worker thread"""
    status: WorkerStatus
    result: Any = None
    error: Optional[str] = None
    progress: float = 0.0


class WorkerThread(ABC, threading.Thread):
    """Base worker thread; subclasses implement `do_work`, report via callbacks."""
    
    def __init__(
        self,
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(daemon=True)
        self.on_progress = on_progress
        self.on_complete = on_complete
        self.on_error = on_error
        self._cancelled = threading.Event()
        self._result_queue: queue.Queue[WorkerResult] = queue.Queue()
        self._status = WorkerStatus.PENDING
    
    @property
    def cancelled(self) -> bool:
        """Check if the worker has been cancelled"""
        return self._cancelled.is_set()
    
    def cancel(self) -> None:
        """Request cancellation of the worker"""
        self._cancelled.set()
    
    def report_progress(self, progress: float, message: str = "") -> None:
        """Report progress (0.0 to 1.0) with optional message"""
        if self.on_progress and not self.cancelled:
            self.on_progress(progress, message)
    
    @abstractmethod
    def do_work(self) -> Any:
        """Override with the actual work; check self.cancelled periodically."""
        pass
    
    def run(self) -> None:
        """Execute the worker thread"""
        self._status = WorkerStatus.RUNNING
        try:
            if self.cancelled:
                result = WorkerResult(status=WorkerStatus.CANCELLED)
            else:
                work_result = self.do_work()
                if self.cancelled:
                    result = WorkerResult(status=WorkerStatus.CANCELLED)
                else:
                    result = WorkerResult(
                        status=WorkerStatus.COMPLETED,
                        result=work_result,
                        progress=1.0,
                    )
            self._status = result.status
        except Exception as e:
            result = WorkerResult(
                status=WorkerStatus.FAILED,
                error=str(e),
            )
            self._status = WorkerStatus.FAILED
            if self.on_error:
                self.on_error(str(e))
        
        self._result_queue.put(result)
        if self.on_complete:
            self.on_complete(result)
    
    def get_result(self, timeout: Optional[float] = None) -> Optional[WorkerResult]:
        """Get the result of the worker (blocking)"""
        try:
            return self._result_queue.get(timeout=timeout)
        except queue.Empty:
            return None


class DiscoveryWorker(WorkerThread):
    """Worker for device discovery operations"""
    
    # Key selector constants
    KEY_ZERO = 1
    KEY_PROVISIONING = 15
    KEY_INTEGRATOR = 14
    KEY_SEED = 13
    
    KEY_NAMES = {
        KEY_ZERO: "Zero",
        KEY_PROVISIONING: "Provisioning",
        KEY_INTEGRATOR: "Integrator", 
        KEY_SEED: "Seed",
    }
    
    def __init__(
        self,
        interface: str,
        keys_file: str,
        pid_range: range,
        timeout_per_device: float = 1.0,
        key_selector: int = 1,  # Default to zero key
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_device_found: Optional[Callable[[int, dict], None]] = None,
    ):
        super().__init__(on_progress, on_complete, on_error)
        self.interface = interface
        self.keys_file = keys_file
        self.pid_range = pid_range
        self.timeout_per_device = timeout_per_device
        self.key_selector = key_selector
        self.on_device_found = on_device_found
    
    def do_work(self) -> List[dict]:
        """Scan network for devices"""
        from ..core.configurator import configurator_init, configurator_destroy
        from ..core.device_discovery import discover_device
        from ..core.logging_util import log_info, log_error, log_debug
        
        key_name = self.KEY_NAMES.get(self.key_selector, f"Key {self.key_selector}")
        log_info("discovery_worker", "Starting device discovery")
        log_info("discovery_worker", "Interface: %s, Keys file: %s", self.interface, self.keys_file)
        log_info("discovery_worker", "PID range: %d-%d, Timeout: %.1fs, Key: %s (%d)", 
                self.pid_range.start, self.pid_range.stop - 1, self.timeout_per_device,
                key_name, self.key_selector)
        
        discovered = []
        total = len(self.pid_range)
        
        log_debug("discovery_worker", "Initializing configurator...")
        try:
            cfg = configurator_init(self.interface, self.keys_file)
            log_info("discovery_worker", "Configurator initialized successfully")
        except Exception as e:
            log_error("discovery_worker", "Failed to initialize configurator: %s", str(e))
            raise
        
        try:
            for i, pid in enumerate(self.pid_range):
                if self.cancelled:
                    log_info("discovery_worker", "Discovery cancelled at PID %d", pid)
                    break
                
                progress = (i + 1) / total
                self.report_progress(progress, f"Scanning PID {pid}...")
                
                log_debug("discovery_worker", "Probing PID %d with key %d...", pid, self.key_selector)
                device = discover_device(cfg, pid, self.timeout_per_device, self.key_selector)
                if device and device.reachable:
                    log_info("discovery_worker", "Found device at PID %d: core=%s, status=0x%02X",
                            pid, device.core_version or "?", device.status or 0)
                    device_info = {
                        "participant_id": device.participant_id,
                        "core_version": device.core_version,
                        "mapping_version": device.mapping_version,
                        "device_identification": device.device_identification,
                        "mcu_serial_number": device.mcu_serial_number,
                        "provisioning_key_id": device.provisioning_key_id,
                        "integrator_key_id": device.integrator_key_id,
                        "seed_key_id": device.seed_key_id,
                        "status": device.status,
                        "last_security_event": device.last_security_event,
                        "response_time_ms": device.response_time_ms,
                    }
                    discovered.append(device_info)
                    if self.on_device_found:
                        self.on_device_found(pid, device_info)
        finally:
            log_debug("discovery_worker", "Destroying configurator...")
            configurator_destroy(cfg)
        
        log_info("discovery_worker", "Discovery complete. Found %d device(s)", len(discovered))
        return discovered


class BootstrapWorker(WorkerThread):
    """Worker for device bootstrapping operations"""
    
    def __init__(
        self,
        interface: str,
        keys_file: str,
        participant_id: int,
        integrator_key: bytes,
        integrator_salt: bytes,
        integrator_key_id: int,
        seed_key: bytes,
        seed_salt: bytes,
        seed_key_id: int,
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(on_progress, on_complete, on_error)
        self.interface = interface
        self.keys_file = keys_file
        self.participant_id = participant_id
        self.integrator_key = integrator_key
        self.integrator_salt = integrator_salt
        self.integrator_key_id = integrator_key_id
        self.seed_key = seed_key
        self.seed_salt = seed_salt
        self.seed_key_id = seed_key_id
    
    def do_work(self) -> int:
        """Bootstrap a device"""
        from ..core.configurator import (
            configurator_init,
            configurator_destroy,
            configurator_bootstrap_device,
        )
        from ..core.logging_util import log_info, log_error, log_debug
        
        log_info("bootstrap_worker", "Starting bootstrap for PID %d", self.participant_id)
        log_info("bootstrap_worker", "Interface: %s, Keys file: %s", self.interface, self.keys_file)
        log_debug("bootstrap_worker", "Integrator key: %d bytes, salt: %d bytes, key_id: %d",
                 len(self.integrator_key), len(self.integrator_salt), self.integrator_key_id)
        log_debug("bootstrap_worker", "Seed key: %d bytes, salt: %d bytes, key_id: %d",
                 len(self.seed_key), len(self.seed_salt), self.seed_key_id)
        
        self.report_progress(0.1, "Initializing connection...")
        log_debug("bootstrap_worker", "Initializing configurator...")
        
        try:
            cfg = configurator_init(self.interface, self.keys_file)
            log_info("bootstrap_worker", "Configurator initialized")
        except Exception as e:
            log_error("bootstrap_worker", "Failed to initialize configurator: %s", str(e))
            raise
        
        try:
            self.report_progress(0.3, "Establishing session...")
            if self.cancelled:
                log_info("bootstrap_worker", "Bootstrap cancelled")
                return -1
            
            self.report_progress(0.5, "Provisioning keys...")
            log_info("bootstrap_worker", "Calling configurator_bootstrap_device...")
            result = configurator_bootstrap_device(
                cfg,
                self.participant_id,
                self.integrator_key,
                self.integrator_salt,
                self.integrator_key_id,
                self.seed_key,
                self.seed_salt,
                self.seed_key_id,
            )
            
            self.report_progress(0.9, "Verifying...")
            log_info("bootstrap_worker", "Bootstrap result: %d", result)
            return result
        except Exception as e:
            log_error("bootstrap_worker", "Bootstrap failed with exception: %s", str(e))
            raise
        finally:
            log_debug("bootstrap_worker", "Destroying configurator...")
            configurator_destroy(cfg)


class SequentialKeyEstablishmentWorker(WorkerThread):
    """Worker for sequential key establishment operations"""
    
    # Key selector constants
    KEY_ZERO = 1
    KEY_PROVISIONING = 15
    KEY_INTEGRATOR = 14
    KEY_SEED = 13
    
    KEY_NAMES = {
        KEY_ZERO: "Zero",
        KEY_PROVISIONING: "Provisioning",
        KEY_INTEGRATOR: "Integrator",
        KEY_SEED: "Seed",
    }
    
    def __init__(
        self,
        interface: str,
        keys_file: str,
        participant_id: int,
        initial_key_selector: int,
        integrator_key: bytes,
        integrator_salt: bytes,
        integrator_key_id: int,
        seed_key: bytes,
        seed_salt: bytes,
        seed_key_id: int,
        provisioning_key: Optional[bytes] = None,
        provisioning_salt: Optional[bytes] = None,
        provisioning_key_id: Optional[int] = None,
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(on_progress, on_complete, on_error)
        self.interface = interface
        self.keys_file = keys_file
        self.participant_id = participant_id
        self.initial_key_selector = initial_key_selector
        self.provisioning_key = provisioning_key
        self.provisioning_salt = provisioning_salt
        self.provisioning_key_id = provisioning_key_id
        self.integrator_key = integrator_key
        self.integrator_salt = integrator_salt
        self.integrator_key_id = integrator_key_id
        self.seed_key = seed_key
        self.seed_salt = seed_salt
        self.seed_key_id = seed_key_id
    
    def do_work(self) -> int:
        """Establish keys sequentially"""
        from ..core.configurator import (
            configurator_init,
            configurator_destroy,
            configurator_establish_keys_sequential,
        )
        from ..core.logging_util import log_info, log_error, log_debug
        
        key_name = self.KEY_NAMES.get(self.initial_key_selector, f"Key {self.initial_key_selector}")
        log_info("sequential_key_worker", "Starting sequential key establishment for PID %d", self.participant_id)
        log_info("sequential_key_worker", "Interface: %s, Keys file: %s", self.interface, self.keys_file)
        log_info("sequential_key_worker", "Initial key selector: %d (%s)", self.initial_key_selector, key_name)
        
        # Determine how many keys will be written
        KEY_SEQUENCE = {
            1: [15, 14, 13],  # Zero → Provisioning → Integrator → Seed
            15: [14, 13],     # Provisioning → Integrator → Seed
            14: [13],         # Integrator → Seed
            13: [],           # Seed → nothing
        }
        keys_to_write = KEY_SEQUENCE.get(self.initial_key_selector, [])
        total_steps = len(keys_to_write) * 3  # Each key: key + salt + key_id
        if total_steps == 0:
            log_info("sequential_key_worker", "No keys to write (starting from Seed)")
            return 0
        
        self.report_progress(0.05, f"Initializing connection with {key_name} key...")
        log_debug("sequential_key_worker", "Initializing configurator...")
        
        try:
            cfg = configurator_init(self.interface, self.keys_file)
            log_info("sequential_key_worker", "Configurator initialized")
        except Exception as e:
            log_error("sequential_key_worker", "Failed to initialize configurator: %s", str(e))
            raise
        
        try:
            if self.cancelled:
                log_info("sequential_key_worker", "Key establishment cancelled")
                return -1
            
            self.report_progress(0.1, f"Establishing keys sequentially (starting with {key_name} key)...")
            log_info("sequential_key_worker", "Calling configurator_establish_keys_sequential...")
            
            result = configurator_establish_keys_sequential(
                cfg,
                self.participant_id,
                self.initial_key_selector,
                provisioning_key=self.provisioning_key,
                provisioning_salt=self.provisioning_salt,
                provisioning_key_id=self.provisioning_key_id,
                integrator_key=self.integrator_key,
                integrator_salt=self.integrator_salt,
                integrator_key_id=self.integrator_key_id,
                seed_key=self.seed_key,
                seed_salt=self.seed_salt,
                seed_key_id=self.seed_key_id,
            )
            
            self.report_progress(0.95, "Verifying...")
            log_info("sequential_key_worker", "Sequential key establishment result: %d", result)
            
            if result == 0:
                self.report_progress(1.0, "Key establishment completed successfully")
            else:
                self.report_progress(0.95, f"Key establishment failed with error: {result}")
            
            return result
        except Exception as e:
            log_error("sequential_key_worker", "Key establishment failed with exception: %s", str(e))
            raise
        finally:
            log_debug("sequential_key_worker", "Destroying configurator...")
            configurator_destroy(cfg)


class FactoryResetWorker(WorkerThread):
    """Worker for factory reset operations"""
    
    def __init__(
        self,
        interface: str,
        keys_file: str,
        participant_id: int,
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        super().__init__(on_progress, on_complete, on_error)
        self.interface = interface
        self.keys_file = keys_file
        self.participant_id = participant_id
    
    def do_work(self) -> int:
        """Perform factory reset"""
        from ..core.configurator import (
            configurator_init,
            configurator_destroy,
            configurator_factory_reset,
        )
        from ..core.logging_util import log_info, log_error, log_debug
        
        log_info("reset_worker", "Starting factory reset for PID %d", self.participant_id)
        log_info("reset_worker", "Interface: %s, Keys file: %s", self.interface, self.keys_file)
        
        self.report_progress(0.1, "Initializing connection...")
        log_debug("reset_worker", "Initializing configurator...")
        
        try:
            cfg = configurator_init(self.interface, self.keys_file)
            log_info("reset_worker", "Configurator initialized")
        except Exception as e:
            log_error("reset_worker", "Failed to initialize configurator: %s", str(e))
            raise
        
        try:
            self.report_progress(0.3, "Establishing session...")
            if self.cancelled:
                log_info("reset_worker", "Factory reset cancelled")
                return -1
            
            self.report_progress(0.5, "Resetting device...")
            log_info("reset_worker", "Calling configurator_factory_reset...")
            result = configurator_factory_reset(cfg, self.participant_id)
            
            self.report_progress(0.9, "Verifying reset...")
            log_info("reset_worker", "Factory reset result: %d", result)
            return result
        except Exception as e:
            log_error("reset_worker", "Factory reset failed with exception: %s", str(e))
            raise
        finally:
            log_debug("reset_worker", "Destroying configurator...")
            configurator_destroy(cfg)


class KeyDistributionWorker(WorkerThread):
    """Worker for distributing keys to group members"""
    
    def __init__(
        self,
        interface: str,
        keys_file: str,
        group_id: int,
        config_file: str = "groups_config.json",
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_device_complete: Optional[Callable[[int, bool], None]] = None,
    ):
        super().__init__(on_progress, on_complete, on_error)
        self.interface = interface
        self.keys_file = keys_file
        self.group_id = group_id
        self.config_file = config_file
        self.on_device_complete = on_device_complete
    
    def do_work(self) -> dict:
        """Distribute keys to all group members"""
        from ..core.configurator import configurator_init, configurator_destroy
        from ..core.group_manager import GroupManager
        from ..core.group_operations import distribute_group_keys
        
        self.report_progress(0.1, "Loading group configuration...")
        group_manager = GroupManager(self.config_file)
        
        group = group_manager.get_group(self.group_id)
        if not group:
            raise ValueError(f"Group {self.group_id} not found")
        
        if not group.member_pids:
            return {"total": 0, "successful": 0, "failed": 0, "failed_pids": []}
        
        self.report_progress(0.2, "Initializing connection...")
        cfg = configurator_init(self.interface, self.keys_file)
        
        try:
            result = distribute_group_keys(cfg, group_manager, self.group_id)
            return {"result_code": result}
        finally:
            configurator_destroy(cfg)


class BatchBootstrapWorker(WorkerThread):
    """Worker for batch bootstrap operations"""
    
    def __init__(
        self,
        interface: str,
        keys_file: str,
        participant_ids: List[int],
        integrator_key: bytes,
        integrator_salt: bytes,
        integrator_key_id: int,
        seed_key: bytes,
        seed_salt: bytes,
        seed_key_id: int,
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_device_complete: Optional[Callable[[int, bool], None]] = None,
    ):
        super().__init__(on_progress, on_complete, on_error)
        self.interface = interface
        self.keys_file = keys_file
        self.participant_ids = participant_ids
        self.integrator_key = integrator_key
        self.integrator_salt = integrator_salt
        self.integrator_key_id = integrator_key_id
        self.seed_key = seed_key
        self.seed_salt = seed_salt
        self.seed_key_id = seed_key_id
        self.on_device_complete = on_device_complete
    
    def do_work(self) -> dict:
        """Bootstrap multiple devices"""
        from ..core.configurator import (
            configurator_init,
            configurator_destroy,
            configurator_bootstrap_device,
        )
        
        successful = 0
        failed = 0
        failed_pids = []
        total = len(self.participant_ids)
        
        cfg = configurator_init(self.interface, self.keys_file)
        
        try:
            for i, pid in enumerate(self.participant_ids):
                if self.cancelled:
                    break
                
                progress = (i + 1) / total
                self.report_progress(progress, f"Bootstrapping PID {pid}...")
                
                result = configurator_bootstrap_device(
                    cfg,
                    pid,
                    self.integrator_key,
                    self.integrator_salt,
                    self.integrator_key_id,
                    self.seed_key,
                    self.seed_salt,
                    self.seed_key_id,
                )
                
                success = result == 0
                if success:
                    successful += 1
                else:
                    failed += 1
                    failed_pids.append(pid)
                
                if self.on_device_complete:
                    self.on_device_complete(pid, success)
        finally:
            configurator_destroy(cfg)
        
        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "failed_pids": failed_pids,
        }


class ProvisionDiscoveredWorker(WorkerThread):
    """Scan a PID range and key-ladder unprovisioned devices from the Zero
    Key (SPsec201 §2.4/§2.5); already-provisioned devices are skipped."""

    def __init__(
        self,
        interface: str,
        keys_file: str,
        start_pid: int,
        end_pid: int,
        provisioning_key: bytes,
        provisioning_salt: bytes,
        provisioning_key_id: int,
        integrator_key: bytes,
        integrator_salt: bytes,
        integrator_key_id: int,
        seed_key: bytes,
        seed_salt: bytes,
        seed_key_id: int,
        timeout: float = 1.0,
        settle_delay: float = 1.0,
        on_progress: Optional[Callable[[float, str], None]] = None,
        on_complete: Optional[Callable[[WorkerResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
        on_device_complete: Optional[Callable[[int, bool], None]] = None,
    ):
        super().__init__(on_progress=on_progress, on_complete=on_complete,
                         on_error=on_error)
        self.interface = interface
        self.keys_file = keys_file
        self.start_pid = start_pid
        self.end_pid = end_pid
        self.provisioning_key = provisioning_key
        self.provisioning_salt = provisioning_salt
        self.provisioning_key_id = provisioning_key_id
        self.integrator_key = integrator_key
        self.integrator_salt = integrator_salt
        self.integrator_key_id = integrator_key_id
        self.seed_key = seed_key
        self.seed_salt = seed_salt
        self.seed_key_id = seed_key_id
        self.timeout = timeout
        self.settle_delay = settle_delay
        self.on_device_complete = on_device_complete

    def do_work(self) -> dict:
        import time as _time
        from ..core.configurator import (
            configurator_init,
            configurator_destroy,
            configurator_establish_keys_sequential,
        )
        from ..core.device_discovery import scan_network, device_is_unprovisioned
        from ..core.spsec_definitions import SPSEC_KEY_SELECTOR_ZERO_KEY

        self.report_progress(0.05, "Scanning for devices...")
        scan_cfg = configurator_init(self.interface, self.keys_file)
        try:
            devices = scan_network(
                scan_cfg, self.start_pid, self.end_pid, self.timeout,
                key_selector=SPSEC_KEY_SELECTOR_ZERO_KEY)
        finally:
            configurator_destroy(scan_cfg)

        found = len(devices)
        targets = [d.participant_id for d in devices if device_is_unprovisioned(d)]
        skipped = found - len(targets)

        if not targets:
            return {"found": found, "total": 0, "successful": 0, "failed": 0,
                    "skipped": skipped, "failed_pids": []}

        # Let the bus and the participants quiesce after the scan's session
        # teardown before starting the ladder against them.
        _time.sleep(self.settle_delay)

        successful, failed, failed_pids = 0, 0, []
        cfg = configurator_init(self.interface, self.keys_file)
        try:
            for i, pid in enumerate(targets):
                if self.cancelled:
                    break
                self.report_progress(0.1 + 0.9 * (i + 1) / len(targets),
                                     f"Provisioning PID {pid}...")
                ret = configurator_establish_keys_sequential(
                    cfg, pid, SPSEC_KEY_SELECTOR_ZERO_KEY,
                    provisioning_key=self.provisioning_key,
                    provisioning_salt=self.provisioning_salt,
                    provisioning_key_id=self.provisioning_key_id,
                    integrator_key=self.integrator_key,
                    integrator_salt=self.integrator_salt,
                    integrator_key_id=self.integrator_key_id,
                    seed_key=self.seed_key,
                    seed_salt=self.seed_salt,
                    seed_key_id=self.seed_key_id,
                )
                ok = ret == 0
                if ok:
                    successful += 1
                else:
                    failed += 1
                    failed_pids.append(pid)
                if self.on_device_complete:
                    self.on_device_complete(pid, ok)
        finally:
            configurator_destroy(cfg)

        return {
            "found": found,
            "total": len(targets),
            "successful": successful,
            "failed": failed,
            "skipped": skipped,
            "failed_pids": failed_pids,
        }


class HeartbeatListener(WorkerThread):
    """Worker that listens for heartbeat broadcasts in the background"""
    
    def __init__(
        self,
        interface: str,
        on_heartbeat: Callable[[int, int], None],
    ):
        super().__init__()
        self.interface = interface
        self.on_heartbeat = on_heartbeat
        
    def do_work(self) -> None:
        """Continuously listen for heartbeats"""
        from ..core.can_interface import can_channel_init, can_channel_receive, can_channel_destroy
        from ..core.spsec_definitions import SPSEC_MSGTYPE_HEARTBEAT
        from ..core.logging_util import log_info, log_debug, log_error
        
        log_info("hb_listener", "Starting heartbeat listener on %s", self.interface)
        try:
            channel = can_channel_init(self.interface)
        except Exception as e:
            log_error("hb_listener", "Failed to init CAN for heartbeat: %s", str(e))
            return
            
        try:
            while not self.cancelled:
                # Use a small timeout to allow checking self.cancelled frequently
                msg = can_channel_receive(channel, timeout_ms=500)
                if msg and msg.msg_type == SPSEC_MSGTYPE_HEARTBEAT:
                    hb = msg.msg_content
                    log_info("hb_listener", "Received heartbeat from PID %d, status 0x%02X", 
                             hb.participant_id, hb.status)
                    if self.on_heartbeat:
                        self.on_heartbeat(hb.participant_id, hb.status)
        finally:
            log_info("hb_listener", "Stopping heartbeat listener")
            can_channel_destroy(channel)

