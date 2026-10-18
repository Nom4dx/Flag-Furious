from app.vendor.magic_wrapper.app import calculate_hashes, normalize_digest, find_hash_matches, ALL_ALGORITHMS

ALGORITHMS = (*ALL_ALGORITHMS, "blake2s")


__all__ = ["calculate_hashes", "normalize_digest", "find_hash_matches", "ALGORITHMS"]
