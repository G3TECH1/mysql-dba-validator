"""A throwaway CA certificate file for tests that configure the connector's CA.

The connector loads the configured CA itself (it builds an ssl.SSLContext), so a
test can no longer point it at a path that does not exist.
"""

import atexit
import datetime
import functools
import shutil
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ca_pem(common_name: str = "Connector Test CA") -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@functools.cache
def company_ca_path() -> str:
    directory = Path(tempfile.mkdtemp(prefix="mdv-test-ca-"))
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    path = directory / "company-ca.pem"
    path.write_text(ca_pem(), encoding="ascii")
    return str(path)
