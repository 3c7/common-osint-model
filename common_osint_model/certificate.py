from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import MD5, SHA1, SHA256
from cryptography.hazmat.backends.openssl.x509 import _Certificate as Certificate
from binascii import hexlify
from typing import Union
from datetime import timezone
from common_osint_model.utils import flatten


def from_x509_pem(pem: Union[str, bytes]) -> dict:
    """
    Converts a certificate in PEM format given as bytes or as string to a dictionary.
    :param pem: PEM certificates as either string or bytes
    :return: dictionary in common format
    """
    g = {}
    if isinstance(pem, str):
        pem = pem.encode("ascii")

    certificate = load_pem_x509_certificate(pem, default_backend())
    g.update(certificate_dn_extraction(certificate))
    g.update(certificate_fingerprint_extraction(certificate))
    g.update(certificate_validity_extraction(certificate))
    g.update(dict(serial_number=certificate.serial_number))
    return g


def from_x509_pem_flattened(pem: Union[str, bytes]) -> dict:
    """
    Wraps from_x509_pem and flattens the output dict
    :param pem: PEM certificates as either string or bytes
    :return: flattened dictionary in common format
    """
    return flatten(from_x509_pem(pem))


def certificate_dn_extraction(certificate: Certificate) -> dict:
    """
    Extracts distinguished names of the given certificate
    :param certificate: object of type cryptography.hazmat.backends.openssl.x509._Certificate
    :return: dictionary containing issuer and subject DN
    """
    dns = dict(subject={}, issuer={})
    terms = dict(
        CN='common_name',
        C='country',
        L='locality',
        ST='province',
        O='organization',
        OU='organizational_unit',
        email='email_address'
    )

    for term in certificate.issuer.rfc4514_string().split(','):
        k, v = term.split("=")
        dns["issuer"].update({
            terms[k.strip()]: v
        })

    for term in certificate.subject.rfc4514_string().split(','):
        k, v = term.split("=")
        dns["subject"].update({
            terms[k.strip()]: v
        })
    return dns


def certificate_fingerprint_extraction(certificate: Certificate) -> dict:
    """
    Calculates certificate fingerprints as MD5, SHA1 and SHA256
    :param certificate: object of type cryptography.hazmat.backends.openssl.x509._Certificate
    :return: dictionary containing all fingerprints
    """
    return {
        "fingerprint": {
            "md5": hexlify(certificate.fingerprint(MD5())).decode("ascii"),
            "sha1": hexlify(certificate.fingerprint(SHA1())).decode("ascii"),
            "sha256": hexlify(certificate.fingerprint(SHA256())).decode("ascii"),
        }
    }


def certificate_validity_extraction(certificate: Certificate) -> dict:
    """
    Extracts validity information of given certificate
    :param certificate: object of type cryptography.hazmat.backends.openssl.x509._Certificate
    :return: dictionary containing the validity timestamps
    """
    return {
        "validity": {
            "start": int(certificate.not_valid_before.timestamp()),
            "start_readable": certificate.not_valid_before.replace(tzinfo=timezone.utc, microsecond=0).isoformat(),
            "end": int(certificate.not_valid_after.timestamp()),
            "end_readable": certificate.not_valid_after.replace(tzinfo=timezone.utc, microsecond=0).isoformat(),
            "length": int((certificate.not_valid_after - certificate.not_valid_before).total_seconds())
        }
    }
