import hashlib
import hmac
import os
from datetime import datetime
from typing import Dict, Optional


class CardHash:
    # Read secret key from environment variable with a default value
    SECRET_KEY = os.environ.get('CARD_HASH_SECRET_KEY', "CHANGE-THIS")
    HASH_LENGTH = 8

    @classmethod
    def _validate_key(cls) -> None:
        """Validate that the secret key has been changed from default."""
        if cls.SECRET_KEY == "CHANGE-THIS":
            raise SecurityError(
                "ERROR: SECRET_KEY environment variable 'CARD_HASH_SECRET_KEY' not set! "
                "Please set this environment variable with a secure secret key before using this system."
            )

    # Rest of the class remains the same
    @classmethod
    def generate_hash(cls,
                      member_id: str,
                      full_name: str,
                      contact: str,
                      has_laser_access: bool,
                      has_key_access: bool,
                      date: str) -> str:
        """Generate an 8-character hash for card data."""
        cls._validate_key()

        laser_access_str = "1" if has_laser_access else "0"
        key_access_str = "1" if has_key_access else "0"
        data = f"{member_id}|{full_name}|{contact}|{laser_access_str}|{key_access_str}|{date}"

        signature = hmac.new(
            cls.SECRET_KEY.encode('utf-8'),
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return signature[:cls.HASH_LENGTH]

    @classmethod
    def verify_hash(cls,
                    member_id: str,
                    full_name: str,
                    contact: str,
                    has_laser_access: bool,
                    has_key_access: bool,
                    date: str,
                    provided_hash: str) -> bool:
        """Verify if a hash is valid."""
        cls._validate_key()
        calculated_hash = cls.generate_hash(
            member_id, full_name, contact,
            has_laser_access, has_key_access, date
        )
        return hmac.compare_digest(calculated_hash, provided_hash)


class SecurityError(Exception):
    """Raised when there's a security-related error."""
    pass


def main():
    # Example card data
    card = {
        "member_id": "0x-0000 0000 0000 0001",
        "full_name": "Example Member",
        "contact": "hackvlc.es",
        "has_laser_access": False,
        "has_key_access": False,
        "date": "16/11/24"
    }

    try:
        # Generate and verify hash silently
        hash_value = CardHash.generate_hash(
            card['member_id'],
            card['full_name'],
            card['contact'],
            card['has_laser_access'],
            card['has_key_access'],
            card['date']
        )

        # Only print the hash
        print(hash_value)

    except SecurityError as e:
        print(e)
        exit(1)


if __name__ == "__main__":
    main()