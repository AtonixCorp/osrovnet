# Post-Quantum Cryptography (PQC) Integration

This document explains the optional post-quantum cryptography features included
with Osrovnet. The code provides safe, informative endpoints even when
optional runtime libraries are not installed.

Supported algorithms (catalog):

- CRYSTALS-Kyber
- CRYSTALS-Dilithium
- Falcon
- SPHINCS+
- NTRU
- BIKE
- FrodoKEM
- Rainbow
- Picnic
- XMSS

Recommended Python packages:

- python-oqs (https://github.com/open-quantum-safe/liboqs)
- pqcrypto (various implementations)

Installation hints (Debian/Ubuntu):

1. Install liboqs and Python bindings (if you want full coverage):

   sudo apt-get install -y build-essential libssl-dev
   # build and install liboqs and python-oqs following upstream docs

2. Install python package in your virtualenv:

   pip install python-oqs

If you cannot or choose not to install these optional libraries, Osrovnet's
`postquantum` app continues to run and returns clear HTTP 501 responses when
operations are requested that require external libraries.

Building a PQC-enabled backend Docker image
-------------------------------------------

If you want to run key generation inside a container, build a PQC-enabled
backend image that compiles and installs liboqs and python-oqs. This is
optional and the build step may take several minutes.

Using the provided Makefile (requires nerdctl / containerd):

```sh
make build-backend-pqc
```

This target builds `osrovnet-backend:local-pqc` and sets a build-arg so the
Dockerfile compiles liboqs and installs `python-oqs`. If you prefer to use
docker, pass `--build-arg PQC=true` to the build command when building
`docker/Dockerfile.backend`.

Security note: building liboqs inside the image increases image size. For
production, consider building liboqs externally and using a smaller final
runtime image (multi-stage) or using a prebuilt liboqs package on your OS.


Security note:

Storing private key material on disk is strongly discouraged. The provided
model defaults to 'none' for private key retention. If you enable private
key storage, ensure keys are stored encrypted and protected by appropriate
access controls.
