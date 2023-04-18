from typing import NamedTuple

from pkilint.cabf.smime import smime_constants
from pkilint.itu import x520_name
from pyasn1.codec.der.encoder import encode
from pyasn1.type import char, univ
from pyasn1_alt_modules import rfc5280

import key
import tbs_builder
import test_keys

_RANDOM_LEI = 'AEYE00EKXESVZUUEBP67'

_CRLDP_BASE_URI = 'http://crl.ca.example.com'
_OCSP_BASE_URI = 'http://ocsp.ca.example.com'
_CA_ISSUERS_BASE_URI = 'http://repository.ca.example.com'


def _build_uri(base_uri, path):
    return f'{base_uri}/{path}'


class CertificateAndKeyPair(NamedTuple):
    certificate: rfc5280.Certificate
    key_pair: key.KeyPair


def _build_ca_rdns(common_name):
    return tbs_builder.build_rdn_sequence([
        (rfc5280.id_at_countryName, char.PrintableString('US')),
        (rfc5280.id_at_organizationName, char.UTF8String('Foo Industries Limited')),
        (rfc5280.id_at_commonName, char.UTF8String(common_name)),
    ])


def _build_ee_org_rdns(extra_rdns=None):
    if extra_rdns is None:
        extra_rdns = []

    return tbs_builder.build_rdn_sequence([
                                              (x520_name.id_at_organizationIdentifier,
                                               char.PrintableString(f'LEIXG-{_RANDOM_LEI}')),
                                              (rfc5280.id_at_organizationName,
                                               char.PrintableString('Acme Industries, Ltd.')),
                                          ] + extra_rdns)


def _build_ee_ja_org_rdns(extra_rdns=None):
    if extra_rdns is None:
        extra_rdns = []

    return tbs_builder.build_rdn_sequence([
                                              (x520_name.id_at_organizationIdentifier,
                                               char.PrintableString(f'LEIXG-{_RANDOM_LEI}')),
                                              (rfc5280.id_at_organizationName, char.UTF8String('アクミ工業株式会社')),
                                          ] + extra_rdns)


def _build_ee_individual_rdns(extra_rdns=None, legacy_name=False):
    if extra_rdns is None:
        extra_rdns = []

    rdns = []

    if not legacy_name:
        rdns.extend([
               (rfc5280.id_at_surname, char.UTF8String('Yamada')),
               (rfc5280.id_at_givenName, char.UTF8String('Hanako')),
           ])

    rdns.append((rfc5280.id_at_commonName, char.UTF8String('YAMADA Hanako')))
    rdns.extend(extra_rdns)

    return tbs_builder.build_rdn_sequence(rdns)


def _build_ee_ja_individual_rdns(extra_rdns=None, legacy_name=False):
    if extra_rdns is None:
        extra_rdns = []

    rdns = []

    if not legacy_name:
        rdns.extend([
            (rfc5280.id_at_surname, char.UTF8String('山田')),
            (rfc5280.id_at_givenName, char.UTF8String('花子')),
        ])

    rdns.append((rfc5280.id_at_commonName, char.UTF8String('山田花子')))
    rdns.extend(extra_rdns)

    return tbs_builder.build_rdn_sequence(rdns)


def _build_ee_sponsored_rdns(extra_rdns=None):
    if extra_rdns is None:
        extra_rdns = []

    return _build_ee_org_rdns([
                                  (rfc5280.id_at_surname, char.UTF8String('Yamada')),
                                  (rfc5280.id_at_givenName, char.UTF8String('Hanako')),
                                  (rfc5280.id_at_commonName, char.UTF8String('YAMADA Hanako'))
                              ] + extra_rdns)


def _build_ee_ja_sponsored_rdns(extra_rdns=None):
    if extra_rdns is None:
        extra_rdns = []

    return _build_ee_ja_org_rdns([
                                  (rfc5280.id_at_surname, char.UTF8String('山田')),
                                  (rfc5280.id_at_givenName, char.UTF8String('花子')),
                                  (rfc5280.id_at_commonName, char.UTF8String('山田花子'))
                              ] + extra_rdns)


def sign_certificate(tbs_certificate: rfc5280.TBSCertificate, key_pair: key.KeyPair):
    tbs_cert_der = encode(tbs_certificate)

    cert = rfc5280.Certificate()
    cert['tbsCertificate'] = tbs_certificate
    cert['signatureAlgorithm'] = key_pair.public_key.signature_algorithm
    cert['signature'] = univ.BitString(hexValue=key_pair.private_key.sign(tbs_cert_der).hex())

    return cert


def sign_crl(tbs_certlist: rfc5280.TBSCertList, key_pair: key.KeyPair):
    tbs_certlist_der = encode(tbs_certlist)

    crl = rfc5280.CertificateList()
    crl['tbsCertList'] = tbs_certlist
    crl['signatureAlgorithm'] = key_pair.public_key.signature_algorithm
    crl['signature'] = univ.BitString(hexValue=key_pair.private_key.sign(tbs_certlist_der).hex())

    return crl


def create_root():
    rsa_key_pair = test_keys.GUTMANN_TESTKEY_P256

    rdns = _build_ca_rdns('Root CA')

    tbs_cert = tbs_builder.build_root(rdns, rsa_key_pair.public_key)

    cert = sign_certificate(tbs_cert, rsa_key_pair)

    tbs_crl = tbs_builder.build_crl(rdns, rsa_key_pair.public_key)
    crl = sign_crl(tbs_crl, rsa_key_pair)

    return CertificateAndKeyPair(cert, rsa_key_pair), crl


def create_ica(root_ca: CertificateAndKeyPair):
    rsa_key_pair = test_keys.GUTMANN_TESTKEY_RSA4096

    rdns = _build_ca_rdns('Intermediate CA')

    extensions = [tbs_builder.build_certificate_policies([rfc5280.anyPolicy]),
                  tbs_builder.build_crldp([_build_uri(_CRLDP_BASE_URI, 'root_crl.crl')]),
                  tbs_builder.build_aia([], [_build_uri(_CA_ISSUERS_BASE_URI, 'root.der')]),
                  tbs_builder.build_eku([rfc5280.id_kp_emailProtection, rfc5280.id_kp_clientAuth])]

    tbs_cert = tbs_builder.build_ica(rdns, rsa_key_pair.public_key,
                                     root_ca.certificate['tbsCertificate']['subject']['rdnSequence'],
                                     root_ca.key_pair.public_key,
                                     extensions)

    cert = sign_certificate(tbs_cert, root_ca.key_pair)

    tbs_crl = tbs_builder.build_crl(rdns, rsa_key_pair.public_key)
    crl = sign_crl(tbs_crl, rsa_key_pair)

    return CertificateAndKeyPair(cert, rsa_key_pair), crl


def _create_ee(ica: CertificateAndKeyPair, validation_level: smime_constants.ValidationLevel,
               generation: smime_constants.Generation, subject_rdns, sans,
               additional_extensions=None, additional_ekus=None, additional_dirname_rdns=None):
    if additional_extensions is None:
        additional_extensions = []
    if additional_ekus is None:
        additional_ekus = []

    rsa_key_pair = test_keys.GUTMANN_TESTKEY_RSA2048

    extensions = [
                     tbs_builder.build_certificate_policies(
                         [smime_constants.get_policy_oid(validation_level, generation)]),
                     tbs_builder.build_crldp([_build_uri(_CRLDP_BASE_URI, 'ica_crl.crl')]),
                     tbs_builder.build_aia([], [_build_uri(_CA_ISSUERS_BASE_URI, 'ica.der')]),
                     tbs_builder.build_eku([rfc5280.id_kp_emailProtection] + additional_ekus),
                     tbs_builder.build_san(sans, add_upn=(rfc5280.id_kp_clientAuth in additional_ekus),
                                           dir_name_rdns=additional_dirname_rdns)
                 ] + additional_extensions

    tbs_cert = tbs_builder.build_ee(subject_rdns, rsa_key_pair.public_key,
                                    ica.certificate['tbsCertificate']['subject']['rdnSequence'],
                                    ica.key_pair.public_key,
                                    extensions
                                    )

    cert = sign_certificate(tbs_cert, ica.key_pair)

    return CertificateAndKeyPair(cert, rsa_key_pair)


def create_ee_mailbox_strict(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = tbs_builder.build_rdn_sequence([
        (rfc5280.id_at_commonName, char.UTF8String(email_address)),
        (rfc5280.id_emailAddress, char.IA5String(email_address))
    ])

    return _create_ee(ica, smime_constants.ValidationLevel.MAILBOX, smime_constants.Generation.STRICT,
                      rdns, email_addresses)


def create_ee_mailbox_multipurpose(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = tbs_builder.build_rdn_sequence([
        (rfc5280.id_at_commonName, char.UTF8String(email_address)),
        (rfc5280.id_emailAddress, char.IA5String(email_address))
    ])

    return _create_ee(ica, smime_constants.ValidationLevel.MAILBOX, smime_constants.Generation.MULTIPURPOSE,
                      rdns, email_addresses, additional_ekus=[rfc5280.id_kp_clientAuth])


def create_ee_org_strict(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = _build_ee_org_rdns(
        [(rfc5280.id_emailAddress, char.IA5String(email_address))]
    )
    ja_rdns = _build_ee_ja_org_rdns()

    lei_ext = tbs_builder.build_lei(_RANDOM_LEI)

    return _create_ee(ica, smime_constants.ValidationLevel.ORGANIZATION, smime_constants.Generation.STRICT,
                      rdns, email_addresses, additional_extensions=[lei_ext], additional_dirname_rdns=ja_rdns)


def create_ee_org_multipurpose(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = _build_ee_org_rdns(
        [(rfc5280.id_emailAddress, char.IA5String(email_address))]
    )
    ja_rdns = _build_ee_ja_org_rdns()

    lei_ext = tbs_builder.build_lei(_RANDOM_LEI)

    return _create_ee(ica, smime_constants.ValidationLevel.ORGANIZATION, smime_constants.Generation.MULTIPURPOSE,
                      rdns, email_addresses, additional_extensions=[lei_ext],
                      additional_ekus=[rfc5280.id_kp_clientAuth], additional_dirname_rdns=ja_rdns)


def create_ee_sponsored_strict(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = _build_ee_sponsored_rdns(
        [(rfc5280.id_emailAddress, char.IA5String(email_address))]
    )
    ja_rdns = _build_ee_ja_sponsored_rdns()

    lei_ext = tbs_builder.build_lei(_RANDOM_LEI)
    lei_role_ext = tbs_builder.build_lei_role('CEO')

    return _create_ee(ica, smime_constants.ValidationLevel.SPONSORED, smime_constants.Generation.STRICT,
                      rdns, email_addresses, additional_extensions=[lei_ext, lei_role_ext],
                      additional_dirname_rdns=ja_rdns)


def create_ee_sponsored_multipurpose(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = _build_ee_sponsored_rdns(
        [(rfc5280.id_emailAddress, char.IA5String(email_address))]
    )
    ja_rdns = _build_ee_ja_sponsored_rdns()

    lei_ext = tbs_builder.build_lei(_RANDOM_LEI)
    lei_role_ext = tbs_builder.build_lei_role('CEO')

    return _create_ee(ica, smime_constants.ValidationLevel.SPONSORED, smime_constants.Generation.MULTIPURPOSE,
                      rdns, email_addresses, additional_extensions=[lei_ext, lei_role_ext],
                      additional_ekus=[rfc5280.id_kp_clientAuth],
                      additional_dirname_rdns=ja_rdns)


def create_ee_individual_strict(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = _build_ee_individual_rdns(
        [(rfc5280.id_emailAddress, char.IA5String(email_address))]
    )
    ja_rdns = _build_ee_ja_individual_rdns()

    return _create_ee(ica, smime_constants.ValidationLevel.INDIVIDUAL, smime_constants.Generation.STRICT,
                      rdns, email_addresses, additional_dirname_rdns=ja_rdns)


def create_ee_individual_multipurpose(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = _build_ee_individual_rdns(
        [(rfc5280.id_emailAddress, char.IA5String(email_address))]
    )
    ja_rdns = _build_ee_ja_individual_rdns()

    return _create_ee(ica, smime_constants.ValidationLevel.INDIVIDUAL, smime_constants.Generation.MULTIPURPOSE,
                      rdns, email_addresses, additional_ekus=[rfc5280.id_kp_clientAuth],
                      additional_dirname_rdns=ja_rdns)


def create_ee_individual_legacy(ica: CertificateAndKeyPair):
    email_address = 'hanako.yamada@example.com'
    email_addresses = [
        email_address,
        '山田花子@example.com',
    ]

    rdns = _build_ee_individual_rdns(
        [(rfc5280.id_emailAddress, char.IA5String(email_address))], legacy_name=True
    )
    ja_rdns = _build_ee_ja_individual_rdns(legacy_name=True)

    return _create_ee(ica, smime_constants.ValidationLevel.INDIVIDUAL, smime_constants.Generation.MULTIPURPOSE,
                      rdns, email_addresses, additional_ekus=[rfc5280.id_kp_clientAuth],
                      additional_dirname_rdns=ja_rdns)
