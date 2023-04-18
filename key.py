import binascii
from abc import ABC
from typing import NamedTuple, Sequence, Tuple, Optional

from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc5480, rfc4055

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


class KeyPair(NamedTuple):
    private_key: 'PrivateKey'
    public_key: 'PublicKey'


_KEY_OID_TO_CONSTRUCTOR = {}


def decode_spki(spki: rfc5280.SubjectPublicKeyInfo) -> 'PublicKey':
    alg_oid = spki['algorithm']['algorithm']

    spki_cons = _KEY_OID_TO_CONSTRUCTOR.get(alg_oid)

    if spki_cons is None:
        raise ValueError(f'Unknown public key algorithm "{str(alg_oid)}"')

    parameters = spki['algorithm']['parameters'] if 'parameters' in spki['algorithm'] else None

    return spki_cons(alg_oid, parameters, spki['subjectPublicKey'].asOctets())


def decode_spki_octets(octets) -> 'PublicKey':
    spki, _ = decode(octets, asn1Spec=rfc5280.SubjectPublicKeyInfo())

    return decode_spki(spki)


def _create_algorithm_identifier(alg_oid, parameters_asn1=None):
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id['algorithm'] = alg_oid
    if parameters_asn1 is not None:
        encoded = encode(parameters_asn1)

        alg_id['parameters'] = encoded

    return alg_id


class PrivateKey(ABC):
    @property
    def raw_octets(self) -> bytes:
        raise NotImplementedError()

    @property
    def encoded(self) -> bytes:
        return self.raw_octets

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def sign(self, message: bytes) -> bytes:
        raise NotImplementedError()


class PublicKey(ABC):
    @property
    def key_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        raise NotImplementedError()

    @property
    def signature_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        raise NotImplementedError()

    @property
    def raw_octets(self) -> bytes:
        raise NotImplementedError()

    @property
    def encoded(self) -> bytes:
        return self.raw_octets

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier) -> bool:
        raise NotImplementedError()

    @property
    def to_spki(self) -> rfc5280.SubjectPublicKeyInfo():
        spki = rfc5280.SubjectPublicKeyInfo()
        spki['algorithm'] = self.key_algorithm
        spki['subjectPublicKey'] = univ.BitString(hexValue=binascii.b2a_hex(self.encoded))

        return spki


_OID_TO_CURVE = {
    rfc5480.secp256r1: ec.SECP256R1,
    rfc5480.secp384r1: ec.SECP384R1,
    rfc5480.secp521r1: ec.SECP521R1,
}

_CURVE_TO_OID = {v: k for k, v in _OID_TO_CURVE.items()}

_CURVE_TO_HASH_CLS = {
    ec.SECP256R1: hashes.SHA256,
    ec.SECP384R1: hashes.SHA384,
    ec.SECP521R1: hashes.SHA512,
}

_CURVE_TO_SIG_ALG = {
    ec.SECP256R1: rfc5480.ecdsa_with_SHA256,
    ec.SECP384R1: rfc5480.ecdsa_with_SHA384,
    ec.SECP521R1: rfc5480.ecdsa_with_SHA512,
}


class EcPublicKey(PublicKey):
    def __init__(self, alg_oid, parameters, octets: bytes):
        if alg_oid != rfc5480.id_ecPublicKey:
            raise ValueError(f'Invalid key algorithm: "{str(alg_oid)}"')

        self._octets = octets
        self._curve_oid, _ = decode(parameters, asn1Spec=univ.ObjectIdentifier())

        curve_cls = _OID_TO_CURVE[self._curve_oid]

        self._backend_instance = ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), octets)

    @property
    def key_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        return _create_algorithm_identifier(rfc5480.id_ecPublicKey, self._curve_oid)

    @property
    def signature_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        return _create_algorithm_identifier(_CURVE_TO_SIG_ALG[type(self._backend_instance.curve)])

    @property
    def raw_octets(self) -> bytes:
        return self._octets

    @property
    def encoded(self) -> bytes:
        return self._backend_instance.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier) -> bool:
        if encode(signature_algorithm) != encode(self.signature_algorithm):
            raise ValueError('ECDSA key and signature algorithm mismatch')

        h_cls = _CURVE_TO_HASH_CLS[type(self._backend_instance.curve)]

        try:
            self._backend_instance.verify(signature, message, ec.ECDSA(h_cls()))

            return True
        except InvalidSignature:
            return False


_KEY_OID_TO_CONSTRUCTOR[rfc5480.id_ecPublicKey] = EcPublicKey


class EcPrivateKey(PrivateKey):
    def __init__(self, cryptography_obj: ec.EllipticCurvePrivateKey):
        self._backend_instance = cryptography_obj

    @property
    def raw_octets(self) -> bytes:
        raise NotImplementedError()

    @property
    def to_pem(self) -> bytes:
        return self._backend_instance.private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                                    serialization.NoEncryption())

    def sign(self, message: bytes) -> bytes:
        h_cls = _CURVE_TO_HASH_CLS[type(self._backend_instance.curve)]

        return self._backend_instance.sign(message, ec.ECDSA(h_cls()))

    @staticmethod
    def load(crypto_private_key: ec.EllipticCurvePrivateKey) -> KeyPair:
        crypto_public_key = crypto_private_key.public_key()
        crypto_public_key_octets = crypto_public_key.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)

        return KeyPair(
            EcPrivateKey(crypto_private_key),
            EcPublicKey(rfc5480.id_ecPublicKey, encode(
                _CURVE_TO_OID[type(crypto_public_key.curve)]), crypto_public_key_octets))

    @staticmethod
    def generate(curve: ec.EllipticCurve) -> KeyPair:
        crypto_private_key = ec.generate_private_key(curve)

        return EcPrivateKey.load(crypto_private_key)


class RsaPkcs15PublicKey(PublicKey):
    def __init__(self, alg_oid, octets: bytes):
        if alg_oid != rfc4055.rsaEncryption:
            raise ValueError(f'Invalid key algorithm: "{str(alg_oid)}"')

        self._octets = octets

        spki = self.to_spki
        spki_octets = encode(spki)

        self._backend_instance = serialization.load_der_public_key(spki_octets)

    @property
    def key_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        return _create_algorithm_identifier(rfc4055.rsaEncryption, univ.Null(''))

    @property
    def signature_algorithm(self) -> rfc5280.AlgorithmIdentifier:
        return _create_algorithm_identifier(rfc4055.sha256WithRSAEncryption, univ.Null(''))

    @property
    def raw_octets(self) -> bytes:
        return self._octets

    def verify(self, message: bytes, signature: bytes, signature_algorithm: rfc5280.AlgorithmIdentifier) -> bool:
        if encode(signature_algorithm) != encode(self.signature_algorithm):
            raise ValueError('RSA key and signature algorithm mismatch')

        try:
            self._backend_instance.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())

            return True
        except InvalidSignature:
            return False


_KEY_OID_TO_CONSTRUCTOR[rfc4055.rsaEncryption] = RsaPkcs15PublicKey


class RsaPkcs15PrivateKey(PrivateKey):
    def __init__(self, cryptography_obj: rsa.RSAPrivateKey):
        self._backend_instance = cryptography_obj

    @property
    def raw_octets(self) -> bytes:
        return self._backend_instance.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.Raw,
                                                    serialization.NoEncryption())

    @property
    def to_pem(self) -> bytes:
        return self._backend_instance.private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                                    serialization.NoEncryption())

    def sign(self, message: bytes) -> bytes:
        return self._backend_instance.sign(message, padding.PKCS1v15(), hashes.SHA256())

    @staticmethod
    def load(crypto_private_key: rsa.RSAPrivateKey) -> KeyPair:
        crypto_public_key = crypto_private_key.public_key()
        crypto_public_key_octets = crypto_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                                  format=serialization.PublicFormat.PKCS1
                                                                  )

        return KeyPair(
            RsaPkcs15PrivateKey(crypto_private_key),
            RsaPkcs15PublicKey(rfc4055.rsaEncryption, crypto_public_key_octets)
        )

    @staticmethod
    def generate(modulus_length: int, exponent: int = 65537) -> KeyPair:
        crypto_private_key = rsa.generate_private_key(exponent, modulus_length)

        return RsaPkcs15PrivateKey.load(crypto_private_key)
