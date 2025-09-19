"""Service wrappers for optional PQC libraries.

Each function attempts to import a recommended library and falls back to a
NotImplementedError with a helpful message if the dependency is missing.
This keeps the app safe to run in environments without PQC libs.
"""
from typing import Dict, Tuple


def list_supported_algorithms() -> Dict[str, str]:
    """Return a mapping of supported algorithm names to short descriptions.

    This is a static list curated for the Osrovnet distribution. Actual
    availability depends on optional runtime libraries (e.g. liboqs,
    pqcrypto, or dedicated Python packages).
    """
    algos = {
        'CRYSTALS-Kyber': 'KEM — lattice-based key exchange (Kyber)',
        'CRYSTALS-Dilithium': 'Signature — lattice-based signatures (Dilithium)',
        'Falcon': 'Signature — lattice-based signature (Falcon)',
        'SPHINCS+': 'Signature — stateless hash-based signature',
        'NTRU': 'Encryption — NTRU encryption scheme',
        'BIKE': 'KEM — code-based key encapsulation (BIKE)',
        'FrodoKEM': 'KEM — LWE-based key exchange (FrodoKEM)',
        'Rainbow': 'Signature — multivariate quadratic signature',
        'Picnic': 'Signature — zero-knowledge based signature',
        'XMSS': 'Signature — stateful Merkle-tree signatures',
    }
    return algos


def generate_keypair(algorithm: str) -> Tuple[bytes, bytes]:
    """Generate a keypair for the given algorithm.

    Returns (public_bytes, private_bytes). If the algorithm is not available
    because the optional dependency is not installed, raise NotImplementedError
    with an install hint.
    """
    alg = algorithm.lower()

    # Try to load liboqs via python-oqs if present for many algorithms
    try:
        import oqs  # type: ignore
    except Exception:
        oqs = None

    if oqs is not None:
        try:
            with oqs.KeyPair(algorithm) as kp:  # type: ignore[attr-defined]
                pub = kp.pk
                priv = kp.sk
                return (pub, priv)
        except Exception:
            # Fall through to algorithm-specific attempts
            pass

    # Fallback: attempt algorithm-specific Python packages (best-effort).
    if 'kyber' in alg:
        raise NotImplementedError('CRYSTALS-Kyber support requires python-oqs or a Kyber package. Install python-oqs or see docs/postquantum.md')

    if 'dilithium' in alg or 'sphincs' in alg or 'falcon' in alg:
        raise NotImplementedError(f'{algorithm} requires a supporting package (e.g. python-oqs). See docs/postquantum.md for installation steps.')

    # Unknown/unimplemented algorithm
    raise NotImplementedError(f'Key generation for {algorithm} is not implemented in this environment. See docs/postquantum.md')
