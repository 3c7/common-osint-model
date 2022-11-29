import binascii
from datetime import datetime
from typing import Dict, List, Optional, Union

import pytz
from cryptography.hazmat.primitives.hashes import MD5, SHA1, SHA256
from cryptography.x509 import OID_COMMON_NAME, ExtensionOID, DNSName, ExtensionNotFound
from cryptography.x509 import load_pem_x509_certificate
from pydantic import BaseModel

from common_osint_model.models import ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger


class TLSComponentCertificateEntity(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler):
    """Represents certificate entities, typically issuer and subject."""
    dn: Optional[str]
    country: Optional[str]
    state: Optional[str]
    locality: Optional[str]
    organization: Optional[str]
    organizational_unit: Optional[str]
    common_name: Optional[str]
    email_address: Optional[str]

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class using a given Shodan data dictionary."""
        if all(key not in d for key in ["C", "L", "CN", "O", "ST"]):
            raise KeyError("The dictionary given to TLSComponentCertificateEntity.from_shodan is missing the typical "
                           "shodan keys.")

        c = d.get("C", None)
        st = d.get("ST", None)
        l = d.get("L", None)
        o = d.get("O", None)
        ou = d.get("OU", None)
        cn = d.get("CN", None)
        email = d.get("emailAddress", None)
        dn = ""
        if c:
            dn += f"C={c}, "
        if st:
            dn += f"ST={st}, "
        if l:
            dn += f"L={l}, "
        if o:
            dn += f"O={o}, "
        if ou:
            dn += f"OU={ou}, "
        if cn:
            if not email:
                dn += f"CN={cn}"
            else:
                dn += f"CN={cn}/Email={email}"
        elif not cn and email:
            dn += f"Email={email}"

        if len(dn) > 0:
            while dn[-1] in [",", " "]:
                dn = dn[:-1]

        return TLSComponentCertificateEntity(
            dn=dn,
            country=c,
            state=st,
            locality=l,
            organization=o,
            organizational_unit=ou,
            common_name=cn,
            email=email
        )

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class based on Censys data given as dictionary."""
        if all(key not in d for key in ["common_name", "locality", "organization", "organizational_unit", "province"]):
            raise KeyError("The dictionary given to TLSComponentCertificateEntity.from_shodan is missing the typical "
                           "censys keys.")

        c = d.get("country", [])
        st = d.get("province", [])
        l = d.get("locality", [])
        o = d.get("organization", [])
        ou = d.get("organizational_unit", [])
        cn = d.get("common_name", [])
        email = d.get("email_address", [])
        dn = ""
        if c:
            for item in c:
                dn += f"C={item}, "
        if st:
            for item in st:
                dn += f"ST={item}, "
        if l:
            for item in l:
                dn += f"L={item}, "
        if o:
            for item in o:
                dn += f"O={item}, "
        if ou:
            for item in ou:
                dn += f"OU={item}, "
        done = False
        if email and cn:
            if len(email) == 1 and len(cn) == 1:
                dn += f"CN={cn[0]}/Email={email[0]}"
                done = True
            else:
                for item in cn:
                    dn += f"CN={item}, "
                for item in email:
                    dn += f"Email={item}, "
                done = True
        if cn and not done:
            for item in cn:
                dn += f"CN={item}, "

        # This one is probably wrong.
        if email and not done:
            for item in email:
                dn += f"Email={item}, "

        while dn[-1] in [" ", ","]:
            dn = dn[:-1]
        return TLSComponentCertificateEntity(
            dn=dn,
            country=", ".join(c),
            state=", ".join(st),
            locality=", ".join(l),
            organization=", ".join(o),
            organizational_unit=", ".join(ou),
            common_name=", ".join(cn),
            email=", ".join(email)
        )

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        c = d.get("country_name", None)
        st = d.get("state_or_province_name", None)
        l = d.get("locality_name", None)
        o = d.get("organization_name", None)
        ou = d.get("organizational_unit_name", None)
        cn = d.get("common_name", None)
        email = d.get("email_address", None)  # Todo: Check if this key is actually correct

        dn = ""
        if c:
            dn += f"C={c}, "
        if st:
            dn += f"ST={st}, "
        if l:
            dn += f"L={l}, "
        if o:
            dn += f"O={o}, "
        if ou:
            dn += f"OU={ou}, "
        if cn:
            if not email:
                dn += f"CN={cn}"
            else:
                dn += f"CN={cn}/Email={email}"
        elif not cn and email:
            dn += f"Email={email}"

        while dn[-1] in [",", " "]:
            dn = dn[:-1]

        return TLSComponentCertificateEntity(
            dn=dn,
            country=c,
            state=st,
            locality=l,
            organization=o,
            organizational_unit=ou,
            common_name=cn,
            email=email
        )


class TLSComponentCertificate(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """Represents certificates."""
    issuer: Optional[TLSComponentCertificateEntity]
    subject: Optional[TLSComponentCertificateEntity]
    issued: Optional[datetime]
    expires: Optional[datetime]
    expired: Optional[bool]
    # More specifically, this is a certificate extension, but we keep it here because it's easier this way.
    alternative_names: Optional[List[str]]
    # The certificate itself
    pem: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    murmur: Optional[str]
    # If the certificate is trusted by the source
    trusted: Optional[bool]

    @property
    def domains(self) -> List[str]:
        domains = []
        if self.subject.common_name:
            domains.append(self.subject.common_name)
        if self.alternative_names:
            domains.extend(self.alternative_names)
        return list(set(domains))

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method TLSComponentCertificate.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        issuer = TLSComponentCertificateEntity.from_shodan(d["ssl"]["cert"]["issuer"])
        subject = TLSComponentCertificateEntity.from_shodan(d["ssl"]["cert"]["subject"])
        issued = datetime.strptime(d["ssl"]["cert"]["issued"], "%Y%m%d%H%M%SZ")
        expires = datetime.strptime(d["ssl"]["cert"]["expires"], "%Y%m%d%H%M%SZ")
        expired = True if d["ssl"]["cert"]["expired"] in ["true", True] else False
        altnames = []
        pem = None
        cert = None
        md5, sha1, sha256 = None, None, None
        certificate_chain = d["ssl"]["chain"]

        trusted = True
        tags = d.get("tags", None)
        if tags:
            if "self-signed" in tags:
                trusted = False

        # If only a single certificate is given in the chain, use it. Also set trusted to false, as this is likely
        # self-signed.
        if len(certificate_chain) == 1:
            pem = certificate_chain[0]
            cert = load_pem_x509_certificate(pem.encode("utf-8"))
        # If there are multiple certificates given, we need to loop over them and compare the common name. This _can_
        # lead to ValueError if the certificates are malformed, such as empty Country values etc. This is why
        # >>> cert.subject.get_attributes_for_oid(OID_COMMON_NAME)
        # is in a try/except block. In these cases, no further data will be extracted from the certificate. However,
        # malformed certificates are often self-signed and the chain length is 1.
        else:
            for cert_pem in d["ssl"]["chain"]:
                cert = load_pem_x509_certificate(cert_pem.encode("utf-8"))
                # Check if this certificate is the leaf certificate by comparing the common name
                attributes = []
                try:
                    attributes = cert.subject.get_attributes_for_oid(OID_COMMON_NAME)
                except:
                    cls.info("Could not get attributes for OID_COMMON_NAME. Skipping this certificate.")
                    continue
                for attribute in attributes:
                    if attribute.value == subject.common_name:
                        pem = cert_pem

        if cert:
            md5, sha1, sha256 = (
                binascii.hexlify(cert.fingerprint(MD5())).decode("utf-8"),
                binascii.hexlify(cert.fingerprint(SHA1())).decode("utf-8"),
                binascii.hexlify(cert.fingerprint(SHA256())).decode("utf-8")
            )

            try:
                ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                altnames.extend(ext.value.get_values_for_type(DNSName))
            except ExtensionNotFound:
                cls.debug("Could not extract alternative names from the certificate extensions.")

        if len(altnames) == 0:
            altnames = None
        else:
            # This removes duplicates
            altnames = list(set(altnames))

        return TLSComponentCertificate(
            issuer=issuer,
            subject=subject,
            issued=issued,
            expires=expires,
            expired=expired,
            alternative_names=altnames,
            pem=pem,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            trusted=trusted
        )

    @classmethod
    def from_censys(cls, d: Dict):
        """Creates an instance of this class based on Censys data given as dictionary."""
        cls.info("Censys does not provide raw certificate data, to hashes must be taken from the data and cannot be "
                 "calculated.")
        trusted = not d.get("signature", {}).get("self_signed", False)
        return TLSComponentCertificate(
            issuer=TLSComponentCertificateEntity.from_censys(d["issuer"]),
            subject=TLSComponentCertificateEntity.from_censys(d["subject"]),
            issued=None,
            expires=None,
            expired=None,
            alternative_names=d.get("names", None),
            sha256=d["fingerprint"],
            trusted=trusted
        )

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        pem = d["as_pem"]
        data = d["as_dict"]
        cert = load_pem_x509_certificate(pem.encode("utf-8"))
        md5, sha1, sha256 = (
            binascii.hexlify(cert.fingerprint(MD5())).decode("utf-8"),
            binascii.hexlify(cert.fingerprint(SHA1())).decode("utf-8"),
            binascii.hexlify(cert.fingerprint(SHA256())).decode("utf-8")
        )
        issued = datetime.fromisoformat(data["validity"]["not_before"]).replace(tzinfo=pytz.utc)
        expires = datetime.fromisoformat(data["validity"]["not_after"]).replace(tzinfo=pytz.utc)
        expired = datetime.utcnow().replace(tzinfo=pytz.utc) < expires
        trusted = not data.get("self_issued", False) or data.get("self_signed", False)
        return TLSComponentCertificate(
            issuer=TLSComponentCertificateEntity.from_binaryedge(data["issuer"]),
            subject=TLSComponentCertificateEntity.from_binaryedge(data["subject"]),
            issued=issued,
            expires=expires,
            expired=expired,
            alternative_names=data["extensions"]["subject_alt_name"],
            pem=pem,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            trusted=trusted
        )


class TLSComponent(BaseModel, ShodanDataHandler, CensysDataHandler, BinaryEdgeDataHandler, Logger):
    """Represents the TLS component of services."""
    certificate: Optional[TLSComponentCertificate]
    ja3: Optional[str]
    ja3s: Optional[str]
    jarm: Optional[str]

    # Todo: Add other attributes relevant to TLS such as CipherSuits etc.

    @classmethod
    def from_shodan(cls, d: Dict):
        """Creates an instance of this class based on Shodan data given as dictionary."""
        if not isinstance(d, Dict):
            raise TypeError(f"Method TLSComponent.from_shodan expects parameter d to be a dictionary, "
                            f"but it was {type(d)}.")

        return TLSComponent(
            certificate=TLSComponentCertificate.from_shodan(d),
            ja3s=d.get("ssl", {}).get("ja3s", None),
            jarm=d.get("ssl", {}).get("jarm", None)
        )

    @classmethod
    def from_censys(cls, d: Dict):
        try:
            tls = d["tls"]
            return TLSComponent(
                certificate=TLSComponentCertificate.from_censys(tls["certificates"]["leaf_data"]),
                ja3s=tls.get("ja3s", None),
                jarm=d.get("jarm", {}).get("fingerprint", None)
            )
        except KeyError as e:
            cls.error(f"Exception during certificate data extraction. "
                      f"The key 'tls.certificates.leaf_data' is not available: {e}\nReturning None...")
            return None

    @classmethod
    def from_binaryedge(cls, d: Union[Dict, List]):
        """Creates an instance of this class based on BinaryEdge data given as dictionary."""
        data = d.get("result", {}).get("data", None)
        if not data:
            cls.error("No data key available in binary edge dictionary. Returning None...")
            return None

        cert = None
        if "cert_info" in data:
            cert = TLSComponentCertificate.from_binaryedge(
                data["cert_info"]["certificate_chain"][0]
            )
        ja3 = None
        if "server_info" in data:
            ja3 = data["server_info"].get("ja3_digest", None)

        jarm = None
        if "jarm_hash" in data:
            jarm = data["jarm_hash"]

        return TLSComponent(
            certificate=cert,
            ja3=ja3,
            jarm=jarm
        )
