import uuid
import time
import threading
from typing import Dict, Optional
from src.methods.frequency.dwt import DWTSteganography


class DWTInstanceManager:
    """Manages DWT steganography instances for embed/extract pairing."""

    _instances: Dict[str, DWTSteganography] = {}
    _instance_timestamps: Dict[str, float] = {}
    _cleanup_thread: Optional[threading.Thread] = None
    _stop_cleanup = False

    @classmethod
    def create_instance(cls, wavelet: str = 'haar', level: int = 1, band: str = 'HL', delta: float = None,
                      embed_level: int = 1, robust_mode: bool = True, header_reps: int = 5,
                      payload_reps: int = 3, interleave_seed: int = 1337, min_delta: float = 5.0) -> str:
        """
        Create a new DWT instance and return its unique ID.

        Args:
            wavelet: Wavelet type (default 'haar')
            level: Decomposition level (default 1)
            band: Frequency band (default 'HL')
            delta: Delta value (default None for adaptive)
            embed_level: Embedding level (default 1)
            robust_mode: Enable robust mode (default True)
            header_reps: Header repetitions (default 5)
            payload_reps: Payload repetitions (default 3)
            interleave_seed: Interleave seed (default 1337)
            min_delta: Minimum delta value (default 5.0)

        Returns:
            Unique instance ID
        """
        instance_id = str(uuid.uuid4())
        cls._instances[instance_id] = DWTSteganography(
            wavelet=wavelet,
            level=level,
            band=band,
            delta=delta,
            embed_level=embed_level,
            robust_mode=robust_mode,
            header_reps=header_reps,
            payload_reps=payload_reps,
            interleave_seed=interleave_seed,
            min_delta=min_delta
        )
        cls._instance_timestamps[instance_id] = time.time()

        # Start cleanup thread if not already running
        if cls._cleanup_thread is None or not cls._cleanup_thread.is_alive():
            cls._start_cleanup_thread()

        return instance_id

    @classmethod
    def get_instance(cls, instance_id: str) -> Optional[DWTSteganography]:
        """
        Retrieve a DWT instance by ID and update its timestamp.

        Args:
            instance_id: Unique instance identifier

        Returns:
            DWT instance if found, None otherwise
        """
        instance = cls._instances.get(instance_id)
        if instance:
            cls._instance_timestamps[instance_id] = time.time()  # Update last accessed time
        return instance

    @classmethod
    def remove_instance(cls, instance_id: str) -> bool:
        """
        Remove a DWT instance by ID.

        Args:
            instance_id: Unique instance identifier

        Returns:
            True if instance was removed, False if not found
        """
        removed = False
        if instance_id in cls._instances:
            del cls._instances[instance_id]
            removed = True
        if instance_id in cls._instance_timestamps:
            del cls._instance_timestamps[instance_id]
        return removed

    @classmethod
    def clear_all_instances(cls) -> None:
        """Clear all stored DWT instances."""
        cls._instances.clear()
        cls._instance_timestamps.clear()

    @classmethod
    def get_instance_count(cls) -> int:
        """Get the number of stored instances."""
        return len(cls._instances)

    @classmethod
    def _cleanup_expired_instances(cls) -> None:
        """Remove instances older than 1 hour."""
        current_time = time.time()
        expiry_time = 3600  # 1 hour in seconds

        expired_instances = []
        for instance_id, timestamp in cls._instance_timestamps.items():
            if current_time - timestamp > expiry_time:
                expired_instances.append(instance_id)

        for instance_id in expired_instances:
            cls.remove_instance(instance_id)

    @classmethod
    def _cleanup_worker(cls) -> None:
        """Background worker thread for cleaning up expired instances."""
        while not cls._stop_cleanup:
            try:
                cls._cleanup_expired_instances()
                time.sleep(300)  # Check every 5 minutes
            except Exception as e:
                print(f"Error in DWT cleanup worker: {e}")

    @classmethod
    def _start_cleanup_thread(cls) -> None:
        """Start the background cleanup thread."""
        if cls._cleanup_thread is None or not cls._cleanup_thread.is_alive():
            cls._stop_cleanup = False
            cls._cleanup_thread = threading.Thread(target=cls._cleanup_worker, daemon=True)
            cls._cleanup_thread.start()

    @classmethod
    def stop_cleanup_thread(cls) -> None:
        """Stop the background cleanup thread."""
        cls._stop_cleanup = True
        if cls._cleanup_thread and cls._cleanup_thread.is_alive():
            cls._cleanup_thread.join(timeout=5)