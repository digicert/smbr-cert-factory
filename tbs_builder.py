import datetime
from typing import Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pkilint import msft
from pkilint.iso import lei
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ, char, useful
from pyasn1_alt_modules import rfc5280, rfc8398

import key


def build_rdn_sequence(rdns: Sequence[Tuple[univ.ObjectIdentifier, char.AbstractCharacterString]]):
    rdn_seq = rfc5280.RDNSequence()

    for oid, value in rdns:
        rdn = rfc5280.RelativeDistinguishedName()

        atv = rfc5280.AttributeTypeAndValue()
        atv['type'] = oid
        atv['value'] = value

        rdn.append(atv)
        rdn_seq.append(rdn)

    return rdn_seq


def calculate_key_identifier(key_octets: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA1())
    h.update(key_octets)

    return h.finalize()


def build_extension(type_oid, pyasn1_value, critical=False):
    ext = rfc5280.Extension()
    ext['extnID'] = type_oid
    ext['critical'] = critical
    ext['extnValue'] = encode(pyasn1_value)

    return ext


def build_basic_constraints(is_ca, path_len=None):
    bc = rfc5280.BasicConstraints()

    bc['cA'] = is_ca

    if path_len is not None:
        bc['pathLenConstraint'] = path_len

    return build_extension(rfc5280.id_ce_basicConstraints, bc, True)


def build_authority_key_identifier(key_octets: bytes):
    aki = rfc5280.AuthorityKeyIdentifier()
    aki['keyIdentifier'] = calculate_key_identifier(key_octets)

    return build_extension(rfc5280.id_ce_authorityKeyIdentifier, aki)


def build_subject_key_identifier(key_octets: bytes):
    ski = rfc5280.SubjectKeyIdentifier(value=calculate_key_identifier(key_octets))

    return build_extension(rfc5280.id_ce_subjectKeyIdentifier, ski)


def _build_validity(validity_duration: datetime.timedelta):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    rfc5280_validity_period = validity_duration - datetime.timedelta(seconds=1)

    not_before = useful.UTCTime(now.strftime('%y%m%d000000Z'))
    not_after = useful.UTCTime((now + rfc5280_validity_period).strftime('%y%m%d235959Z'))

    return not_before, not_after


def build_keyusage(value):
    ku = rfc5280.KeyUsage(value=value)

    return build_extension(rfc5280.id_ce_keyUsage, ku, True)


def build_certificate_policies(oids):
    cp = rfc5280.CertificatePolicies()

    for oid in oids:
        pi = rfc5280.PolicyInformation()
        pi['policyIdentifier'] = univ.ObjectIdentifier(oid)

        cp.append(pi)

    return build_extension(rfc5280.id_ce_certificatePolicies, cp)


def build_crldp(uris):
    crldp = rfc5280.CRLDistributionPoints()

    for uri in uris:
        dp = rfc5280.DistributionPoint()

        gn = rfc5280.GeneralName()
        gn.setComponentByName('uniformResourceIdentifier', uri)

        dp['distributionPoint']['fullName'].append(gn)

        crldp.append(dp)

    return build_extension(rfc5280.id_ce_cRLDistributionPoints, crldp)


def build_eku(kps):
    eku = rfc5280.ExtKeyUsageSyntax()

    for kp in kps:
        eku.append(univ.ObjectIdentifier(kp))

    return build_extension(rfc5280.id_ce_extKeyUsage, eku)


def build_aia(ocsp_uris, issuer_ca_uris):
    aia = rfc5280.AuthorityInfoAccessSyntax()

    for ocsp_uri in ocsp_uris:
        ad = rfc5280.AccessDescription()
        ad['accessMethod'] = rfc5280.id_ad_ocsp
        ad['accessLocation'].setComponentByName('uniformResourceIdentifier', ocsp_uri)

        aia.append(ad)

    for issuer_ca_uri in issuer_ca_uris:
        ad = rfc5280.AccessDescription()
        ad['accessMethod'] = rfc5280.id_ad_caIssuers
        ad['accessLocation'].setComponentByName('uniformResourceIdentifier', issuer_ca_uri)

        aia.append(ad)

    return build_extension(rfc5280.id_pe_authorityInfoAccess, aia)


def build_lei(lei_number):
    ext_value = lei.Lei(lei_number)

    return build_extension(lei.id_ce_lei, ext_value)


def build_lei_role(lei_role):
    ext_value = lei.Role(lei_role)

    return build_extension(lei.id_ce_role, ext_value)


def build_san(email_addresses, critical=False, add_upn=False, dir_name_rdns=None):
    san = rfc5280.SubjectAltName()

    for email_address in email_addresses:
        gn = rfc5280.GeneralName()

        local_part, domain_part = email_address.split('@', maxsplit=1)

        if not local_part.isascii():
            on = gn.getComponentByName('otherName')
            on['type-id'] = rfc8398.id_on_SmtpUTF8Mailbox
            on['value'] = char.UTF8String(email_address)
        else:
            gn.setComponentByName('rfc822Name', email_address)

        san.append(gn)

        if local_part.isascii() and add_upn:
            gn = rfc5280.GeneralName()

            on = gn.getComponentByName('otherName')
            on['type-id'] = msft.asn1.id_on_UserPrincipalName
            on['value'] = msft.asn1.UserPrincipalName(email_address)

            san.append(gn)

    if dir_name_rdns:
        gn = rfc5280.GeneralName()

        n = gn['directoryName']
        n['rdnSequence'] = dir_name_rdns

        san.append(gn)

    return build_extension(rfc5280.id_ce_subjectAltName, san, critical)


def build_tbscertificate(
        subject_public_key: key.PublicKey,
        issuer_public_key: key.PublicKey,
        issuer_name, subject_name,
        duration_days,
        extensions
):
    tbs_cert = rfc5280.TBSCertificate()
    tbs_cert['version'] = rfc5280.Version.namedValues['v3']
    tbs_cert['serialNumber'] = univ.Integer(x509.random_serial_number())

    tbs_cert['signature'] = issuer_public_key.signature_algorithm

    tbs_cert['issuer']['rdnSequence'] = issuer_name

    validity = rfc5280.Validity()
    not_before, not_after = _build_validity(datetime.timedelta(days=duration_days))
    validity['notBefore']['utcTime'] = not_before
    validity['notAfter']['utcTime'] = not_after

    tbs_cert['validity'] = validity

    tbs_cert['subject']['rdnSequence'] = subject_name

    tbs_cert['subjectPublicKeyInfo'] = subject_public_key.to_spki

    tbs_cert['extensions'].extend(extensions)

    return tbs_cert


def build_root(subject_dn, public_key):
    return build_tbscertificate(
        public_key,
        public_key,
        subject_dn, subject_dn,
        360,
        [build_basic_constraints(True),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(public_key.encoded),
         build_subject_key_identifier(public_key.encoded)]
    )


def build_ica(subject_dn, subject_public_key, issuer_dn, issuer_public_key, extensions=None):
    if extensions is None:
        extensions = []

    return build_tbscertificate(
        subject_public_key,
        issuer_public_key,
        issuer_dn, subject_dn,
        180,
        [build_basic_constraints(True, 0),
         build_keyusage('digitalSignature,cRLSign,keyCertSign'),
         build_authority_key_identifier(issuer_public_key.encoded),
         build_subject_key_identifier(subject_public_key.encoded)] + extensions
    )


def build_ee(subject_dn, subject_public_key, issuer_dn, issuer_public_key, extensions=None, key_usages=None):
    if key_usages is None:
        key_usages = ['digitalSignature']
    if extensions is None:
        extensions = []

    return build_tbscertificate(
        subject_public_key, issuer_public_key,
        issuer_dn, subject_dn,
        90,
        [build_basic_constraints(False),
         build_keyusage(','.join(key_usages)),
         build_authority_key_identifier(issuer_public_key.encoded),
         build_subject_key_identifier(subject_public_key.encoded)] + extensions
    )


def build_crl(issuer_dn, issuer_public_key):
    tbs_crl = rfc5280.TBSCertList()
    tbs_crl['version'] = rfc5280.Version.namedValues['v2']

    tbs_crl['signature'] = issuer_public_key.signature_algorithm

    tbs_crl['issuer']['rdnSequence'] = issuer_dn
    this_update, next_update = _build_validity(datetime.timedelta(days=7))
    tbs_crl['thisUpdate']['utcTime'] = this_update
    tbs_crl['nextUpdate']['utcTime'] = next_update

    tbs_crl['crlExtensions'].extend((
        build_extension(rfc5280.id_ce_cRLNumber, rfc5280.CRLNumber(1), False),
        build_authority_key_identifier(issuer_public_key.encoded),
    ))

    return tbs_crl
