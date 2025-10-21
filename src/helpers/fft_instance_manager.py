import uuid
import time
import threading
from typing import Dict, Optional
from src.methods.frequency.fft import FFTSteganography


class FFTInstanceManager:
    """Manages FFT steganography instances for embed/extract pairing."""

    _instances: Dict[str, FFTSteganography] = {}
    _instance_timestamps: Dict[str, float] = {}
    _cleanup_thread: Optional[threading.Thread] = None
    _stop_cleanup = False

    @classmethod
    def create_instance(cls, r_in: float = 0.30, r_out: float = 0.50, phase_levels: int = 4,
                      header_repeat: int = 5, payload_repeat: int = 3, color_order: str = "RGB",
                      header_channel: str = "Y", payload_channel: str = "Cb",
                      mag_min_boost: float = 3.0) -> str:
        """
        Create a new FFT instance and return its unique ID.

        Args:
            r_in: Inner radius ratio (default 0.30)
            r_out: Outer radius ratio (default 0.50)
            phase_levels: Phase levels (locked to 4)
            header_repeat: Header repeat count (default 5)
            payload_repeat: Payload repeat count (default 3)
            color_order: Color order (RGB or BGR, default RGB)
            header_channel: Header channel (Y, Cr, Cb, default Y)
            payload_channel: Payload channel (Y, Cr, Cb, default Cb)
            mag_min_boost: Minimum magnitude boost (default 3.0)

        Returns:
            Unique instance ID
        """
        instance_id = str(uuid.uuid4())
        cls._instances[instance_id] = FFTSteganography(
            r_in=r_in,
            r_out=r_out,
            phase_levels=phase_levels,
            header_repeat=header_repeat,
            payload_repeat=payload_repeat,
            color_order=color_order,
            header_channel=header_channel,
            payload_channel=payload_channel,
            mag_min_boost=mag_min_boost
        )
        cls._instance_timestamps[instance_id] = time.time()

        # Start cleanup thread if not already running
        if cls._cleanup_thread is None or not cls._cleanup_thread.is_alive():
            cls._start_cleanup_thread()

        return instance_id

    @classmethod
    def get_instance(cls, instance_id: str) -> Optional[FFTSteganography]:
        """
        Retrieve an FFT instance by ID and update its timestamp.

        Args:
            instance_id: Unique instance identifier

        Returns:
            FFT instance if found, None otherwise
        """
        instance = cls._instances.get(instance_id)
        if instance:
            cls._instance_timestamps[instance_id] = time.time()  # Update last accessed time
        return instance

    @classmethod
    def remove_instance(cls, instance_id: str) -> bool:
        """
        Remove an FFT instance by ID.

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
        """Clear all stored FFT instances."""
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
                print(f"Error in FFT cleanup worker: {e}")

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