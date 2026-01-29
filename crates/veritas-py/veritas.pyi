"""
Type stubs for VERITAS Python bindings.

This file provides type hints for IDE support and static type checking.
"""

from typing import List, Optional

class VeritasError(Exception):
    """VERITAS error exception.

    Raised when VERITAS operations fail.
    """
    pass

class IdentityInfo:
    """Information about an identity.

    Attributes:
        hash: The identity hash in hex format.
        label: User-friendly label for this identity.
        is_primary: Whether this is the primary identity.
        created_at: Unix timestamp when the identity was created.
        is_usable: Whether this identity can be used for operations.
        is_expiring: Whether this identity is in the expiring warning period.
        key_state: Current state of the identity keys.
    """
    hash: str
    label: Optional[str]
    is_primary: bool
    created_at: int
    is_usable: bool
    is_expiring: bool
    key_state: str

class IdentitySlots:
    """Information about identity slot usage.

    Each device origin is limited to 3 identities.

    Attributes:
        used: Number of slots currently in use.
        max: Maximum allowed slots per origin (always 3).
        available: Number of slots available for new identities.
        next_slot_available: Unix timestamp when the next slot will become
            available, or None if slots are available.
    """
    used: int
    max: int
    available: int
    next_slot_available: Optional[int]

    def can_create(self) -> bool:
        """Check if a new identity can be created.

        Returns:
            True if a slot is available for a new identity.
        """
        ...

class SafetyNumber:
    """A safety number for verifying secure communication between two parties.

    Safety numbers allow users to verify they are communicating with the
    correct party by comparing these values out-of-band (in person, phone call,
    or QR code scan).

    Both parties compute the same safety number from their combined public keys.
    If the safety numbers match, users can be confident they have the correct keys
    and are protected against man-in-the-middle attacks.
    """

    @staticmethod
    def compute(our_keys: bytes, their_keys: bytes) -> 'SafetyNumber':
        """Compute a safety number from two identities' public keys.

        The computation is symmetric: swapping the arguments produces
        the same result. This ensures both parties compute identical
        safety numbers.

        Args:
            our_keys: Our identity's public keys (bytes).
            their_keys: The other party's public keys (bytes).

        Returns:
            A safety number that both parties can compare.

        Raises:
            VeritasError: If the keys are invalid.

        Example:
            >>> alice_keys = client1.public_keys()
            >>> bob_keys = client2.public_keys()
            >>> safety = SafetyNumber.compute(alice_keys, bob_keys)
            >>> print(safety)  # Display for verbal comparison
        """
        ...

    def to_numeric_string(self) -> str:
        """Format the safety number as a 60-digit numeric string.

        The output is formatted as 12 groups of 5 digits, separated by spaces.
        This format is ideal for verbal comparison between users.

        Returns:
            60 digits in format "XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX"

        Example:
            >>> numeric = safety.to_numeric_string()
            >>> print(f"Verify these digits: {numeric}")
        """
        ...

    def to_qr_string(self) -> str:
        """Format the safety number as a hex string for QR codes.

        Returns a 64-character lowercase hex string representing
        all 32 bytes. This format is ideal for QR code generation
        and automated verification.

        Returns:
            64-character hex string.

        Example:
            >>> qr_data = safety.to_qr_string()
            >>> # Generate QR code with qr_data
        """
        ...

    def as_bytes(self) -> bytes:
        """Get the raw bytes of the safety number.

        Returns:
            The 32-byte safety number value.
        """
        ...

    def __str__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...

class VeritasClient:
    """The main VERITAS protocol client.

    Provides a high-level API for:
    - Identity management
    - Encrypted messaging
    - Group conversations
    - Blockchain verification
    - Reputation tracking

    The client follows a state machine pattern and must be unlocked
    before use.

    Example:
        >>> # Create in-memory client
        >>> client = VeritasClient()
        >>> client.unlock(b"my_password")
        >>>
        >>> # Create identity
        >>> identity_hash = client.create_identity("Personal")
        >>> print(f"Created identity: {identity_hash}")
        >>>
        >>> # Lock when done
        >>> client.lock()

    Example:
        >>> # Create client with persistent storage
        >>> client = VeritasClient(path="/path/to/data")
        >>> client.unlock(b"my_password")
        >>> # ... use client ...
        >>> client.shutdown()
    """

    def __init__(self, path: Optional[str] = None) -> None:
        """Create a new VERITAS client.

        Args:
            path: Optional path to data directory. If not provided,
                  uses in-memory storage (data lost on shutdown).

        Raises:
            VeritasError: If client creation fails.

        Example:
            >>> # In-memory client
            >>> client = VeritasClient()
            >>>
            >>> # Persistent storage
            >>> client = VeritasClient(path="/data/veritas")
        """
        ...

    # Lifecycle Methods

    def unlock(self, password: bytes) -> None:
        """Unlock the client with a password.

        This initializes all services and decrypts stored identity keys.
        The client must be unlocked before performing any operations.

        Args:
            password: The password or key material for decryption (bytes).

        Raises:
            VeritasError: If unlock fails (wrong password, already unlocked, etc.)

        Example:
            >>> client = VeritasClient()
            >>> client.unlock(b"my_secure_password")
        """
        ...

    def lock(self) -> None:
        """Lock the client and zeroize sensitive data.

        After locking, the client cannot be used for operations until
        unlocked again. This is recommended when the client is idle.

        Raises:
            VeritasError: If locking fails.

        Example:
            >>> client.lock()
            >>> # Later, unlock again
            >>> client.unlock(b"my_secure_password")
        """
        ...

    def shutdown(self) -> None:
        """Shutdown the client completely.

        This performs a clean shutdown:
        - Stops accepting new operations
        - Waits for pending operations to complete
        - Closes network connections
        - Persists any pending data
        - Zeroizes all sensitive data

        After shutdown, the client cannot be reused.

        Raises:
            VeritasError: If shutdown fails.

        Example:
            >>> client.shutdown()
        """
        ...

    def is_unlocked(self) -> bool:
        """Check if the client is unlocked and ready for operations.

        Returns:
            True if the client is unlocked.

        Example:
            >>> if client.is_unlocked():
            ...     print("Client is ready")
        """
        ...

    def state(self) -> str:
        """Get the current client state.

        Returns:
            The current state ("Created", "Locked", "Unlocked", or "ShuttingDown").

        Example:
            >>> state = client.state()
            >>> print(f"Client state: {state}")
        """
        ...

    # Identity Methods

    def identity_hash(self) -> str:
        """Get the hash of the primary identity.

        The primary identity is used by default for all operations.

        Returns:
            The identity hash in hex format.

        Raises:
            VeritasError: If the client is not unlocked or no primary identity is set.

        Example:
            >>> hash = client.identity_hash()
            >>> print(f"My identity: {hash}")
        """
        ...

    def public_keys(self) -> bytes:
        """Get the public keys of the primary identity.

        These keys can be shared with others to enable encrypted communication.

        Returns:
            Serialized public keys.

        Raises:
            VeritasError: If the client is not unlocked or no primary identity is set.

        Example:
            >>> keys = client.public_keys()
            >>> # Share keys with a contact
        """
        ...

    def create_identity(self, label: Optional[str] = None) -> str:
        """Create a new identity.

        Args:
            label: Optional human-readable label for the identity.

        Returns:
            The hash of the created identity in hex format.

        Raises:
            VeritasError: If the client is not unlocked or the maximum
                          identities per origin has been reached.

        Example:
            >>> # Create with label
            >>> hash = client.create_identity("Personal")
            >>>
            >>> # Create without label
            >>> hash = client.create_identity()
        """
        ...

    def list_identities(self) -> List[IdentityInfo]:
        """List all identities managed by this client.

        Returns:
            List of identity information objects.

        Raises:
            VeritasError: If the client is not unlocked.

        Example:
            >>> identities = client.list_identities()
            >>> for identity in identities:
            ...     print(f"{identity.hash}: {identity.label}")
        """
        ...

    def set_primary_identity(self, hash: str) -> None:
        """Set the primary identity.

        The primary identity is used by default for all operations.

        Args:
            hash: The identity hash in hex format.

        Raises:
            VeritasError: If the client is not unlocked or the identity is not found.

        Example:
            >>> identities = client.list_identities()
            >>> client.set_primary_identity(identities[1].hash)
        """
        ...

    def identity_slots(self) -> IdentitySlots:
        """Get information about identity slot usage.

        Each device origin is limited to 3 identities. This method returns
        information about how many slots are used and available.

        Returns:
            Information about slot usage.

        Raises:
            VeritasError: If the client is not unlocked.

        Example:
            >>> slots = client.identity_slots()
            >>> print(f"Used {slots.used}/{slots.max} identity slots")
            >>> if slots.can_create():
            ...     client.create_identity("Work")
        """
        ...

def version() -> str:
    """Get the library version.

    Returns:
        The version string.

    Example:
        >>> import veritas
        >>> print(veritas.version())
    """
    ...
