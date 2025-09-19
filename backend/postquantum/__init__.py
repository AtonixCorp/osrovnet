"""Post-quantum cryptography helpers for Osrovnet.

This app provides lightweight API endpoints and service wrappers for
post-quantum cryptography (PQC) operations such as key generation and
algorithm discovery. Implementations are optional — if the runtime
doesn't have PQC libraries installed, endpoints return helpful messages
and instructions.
"""

default_app_config = 'postquantum.apps.PostquantumConfig'
