import base64
import os
import shutil
import urllib.parse

from cryptography.hazmat.primitives import serialization
from pyasn1_alt_modules import rfc5280

import templates
from pyasn1.codec.der.encoder import encode
from cryptography import x509


def _persist(cert_key_pair: templates.CertificateAndKeyPair, label: str):
    key_filename = f'{label}.key'

    if hasattr(cert_key_pair.key_pair.private_key, 'to_pem'):
        key_data = cert_key_pair.key_pair.private_key.to_pem
    else:
        key_data = cert_key_pair.key_pair.private_key.raw_octets

    with open(key_filename, 'wb') as f:
        f.write(key_data)

    cert_filename = f'{label}.der'

    der = encode(cert_key_pair.certificate)

    with open(cert_filename, 'wb') as f:
        f.write(der)

    cert_filename = f'{label}.pem'

    crypto_cert = x509.load_der_x509_certificate(der)

    with open(cert_filename, 'wb') as f:
        f.write(crypto_cert.public_bytes(serialization.Encoding.PEM))

    b64_escaped = urllib.parse.quote(base64.b64encode(der).decode())

    link_title = label.title().replace('_', ' ')

    print(f'* [{link_title}](https://understandingwebpki.com?cert={b64_escaped})')


def _persist_crl(signed_crl: rfc5280.CertificateList, label: str):
    crl_filename = f'{label}.crl'

    der = encode(signed_crl)

    with open(crl_filename, 'wb') as f:
        f.write(der)

    link_title = label.title().replace('_', ' ')

    b64_escaped = urllib.parse.quote(base64.b64encode(der).decode())

    # print(f'* [{link_title}](https://understandingwebpki.com?crl={b64_escaped})')


shutil.rmtree('artifacts', True)
os.makedirs('artifacts', exist_ok=True)

os.chdir('artifacts')

root, root_crl = templates.create_root()
_persist(root, 'root_ca')
_persist_crl(root_crl, 'root_ca_crl')

ica, ica_crl = templates.create_ica(root)
_persist(ica, 'issuing_ca')
_persist_crl(ica_crl, 'issuing_ca_crl')

ee_mailbox_strict = templates.create_ee_mailbox_strict(ica)
_persist(ee_mailbox_strict, 'mailbox-validated_strict')

ee_mailbox_multipurpose = templates.create_ee_mailbox_multipurpose(ica)
_persist(ee_mailbox_multipurpose, 'mailbox-validated_multipurpose')

ee_org_strict = templates.create_ee_org_strict(ica)
_persist(ee_org_strict, 'organization-validated_strict')

ee_org_multipurpose = templates.create_ee_org_multipurpose(ica)
_persist(ee_org_multipurpose, 'organization-validated_multipurpose')

ee_sponsored_strict = templates.create_ee_sponsored_strict(ica)
_persist(ee_sponsored_strict, 'sponsored-validated_strict')

ee_sponsored_multipurpose = templates.create_ee_sponsored_multipurpose(ica)
_persist(ee_sponsored_multipurpose, 'sponsored-validated_multipurpose')

ee_individual_strict = templates.create_ee_individual_strict(ica)
_persist(ee_individual_strict, 'individual-validated_strict')

ee_individual_multipurpose = templates.create_ee_individual_multipurpose(ica)
_persist(ee_individual_multipurpose, 'individual-validated_multipurpose')

ee_individual_legacy = templates.create_ee_individual_legacy(ica)
_persist(ee_individual_legacy, 'individual-validated_legacy')
