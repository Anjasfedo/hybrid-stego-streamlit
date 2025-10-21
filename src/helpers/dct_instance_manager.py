import uuid
import time
import threading
from typing import Dict, Optional, List, Tuple
from src.methods.frequency.dct import DCTSteganography

# DCT embed position presets
POSITION_MID_LOW = [(1, 1), (2, 0), (0, 2), (3, 0), (0, 3)]
POSITION_MID = [(2, 1), (1, 2), (2, 2), (3, 1), (1, 3)]
POSITION_HIGH = [(4, 4), (5, 3), (3, 5), (6, 2), (2, 6)]


class DCTInstanceManager:
    """Manages DCT steganography instances for embed/extract pairing."""

    _instances: Dict[str, DCTSteganography] = {}
    _instance_timestamps: Dict[str, float] = {}
    _cleanup_thread: Optional[threading.Thread] = None
    _stop_cleanup = False

    @classmethod
    def create_instance(cls, block_size: int = 8, quant_factor: int = 70, embed_positions: List[Tuple[int, int]] = None) -> str:
        """
        Create a new DCT instance and return its unique ID.

        Args:
            block_size: Block size for DCT (default 8)
            quant_factor: Quantization factor (default 70, higher for robustness but lower quality)
            embed_positions: List of embed positions (default POSITION_MID)

        Returns:
            Unique instance ID
        """
        if embed_positions is None:
            embed_positions = POSITION_MID

        instance_id = str(uuid.uuid4())
        cls._instances[instance_id] = DCTSteganography(
            block_size=block_size,
            quant_factor=quant_factor,
            embed_positions=embed_positions
        )
        cls._instance_timestamps[instance_id] = time.time()

        # Start cleanup thread if not already running
        if cls._cleanup_thread is None or not cls._cleanup_thread.is_alive():
            cls._start_cleanup_thread()

        return instance_id

    @classmethod
    def get_instance(cls, instance_id: str) -> Optional[DCTSteganography]:
        """
        Retrieve a DCT instance by ID and update its timestamp.

        Args:
            instance_id: Unique instance identifier

        Returns:
            DCT instance if found, None otherwise
        """
        instance = cls._instances.get(instance_id)
        if instance:
            cls._instance_timestamps[instance_id] = time.time()  # Update last accessed time
        return instance

    @classmethod
    def remove_instance(cls, instance_id: str) -> bool:
        """
        Remove a DCT instance by ID.

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
        """Clear all stored DCT instances."""
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
                print(f"Error in DCT cleanup worker: {e}")

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