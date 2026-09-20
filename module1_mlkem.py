import os
import secrets
import hashlib
from dataclasses import dataclass

@dataclass
class MlKemKeyPair:
    publicKey: bytes
    privateKey: bytes

@dataclass
class MlKemEncapsulation:
    cipherText: bytes
    sharedSecret: bytes


_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD"
    "129024E088A67CC74020BBEA63B139B22514A08798E3404"
    "DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C"
    "245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406"
    "B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE"
    "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD"
    "24CF5F83655D23DCA3AD961C62F356208552BB9ED529077"
    "096966D670C354E4ABC9804F1746C08CA18217C32905E46"
    "2E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF"
    "06F4C52C9DE2BCBF6955817183995497CEA956AE515D226"
    "1898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH_G = 2
_DH_KEY_BYTES = 256  


class MlKem768:
    def __init__(self):
        self.algorithmName = "ML-KEM-768"
        self._useNative = False
        try:
            from cryptography.hazmat.primitives.asymmetric import mlkem
            self._mlkem = mlkem
            self._useNative = True
        except (ImportError, AttributeError):
            self._useNative = False

    def generateKeyPair(self) -> MlKemKeyPair:
        if self._useNative:
            privKeyObj = self._mlkem.MLKEM768PrivateKey.generate()
            pubKeyObj = privKeyObj.public_key()
            return MlKemKeyPair(
                publicKey=pubKeyObj.public_bytes_raw(),
                privateKey=privKeyObj.private_bytes_raw())

        privateInt = secrets.randbelow(_DH_P - 2) + 1
        publicInt = pow(_DH_G, privateInt, _DH_P)
        return MlKemKeyPair(
            publicKey=publicInt.to_bytes(_DH_KEY_BYTES, "big"),
            privateKey=privateInt.to_bytes(_DH_KEY_BYTES, "big"),)

    def encapsulate(self, peerPublicKey: bytes) -> MlKemEncapsulation:
        if self._useNative:
            pubKeyObj = self._mlkem.MLKEM768PublicKey.from_public_bytes(peerPublicKey)
            sharedSecret, cipherText = pubKeyObj.encapsulate()
            return MlKemEncapsulation(cipherText=cipherText, sharedSecret=sharedSecret)

        peerPublicInt = int.from_bytes(peerPublicKey, "big")
        ephemeralPrivateInt = secrets.randbelow(_DH_P - 2) + 1
        ephemeralPublicInt = pow(_DH_G, ephemeralPrivateInt, _DH_P)
        sharedInt = pow(peerPublicInt, ephemeralPrivateInt, _DH_P)
        sharedSecret = hashlib.sha3_256(sharedInt.to_bytes(_DH_KEY_BYTES, "big")).digest()
        cipherText = ephemeralPublicInt.to_bytes(_DH_KEY_BYTES, "big")
        return MlKemEncapsulation(cipherText=cipherText, sharedSecret=sharedSecret)

    def decapsulate(self, cipherText: bytes, privateKey: bytes) -> bytes:
        if self._useNative:
            privKeyObj = self._mlkem.MLKEM768PrivateKey.from_seed_bytes(privateKey)
            return privKeyObj.decapsulate(cipherText)

        ephemeralPublicInt = int.from_bytes(cipherText, "big")
        privateInt = int.from_bytes(privateKey, "big")
        sharedInt = pow(ephemeralPublicInt, privateInt, _DH_P)
        return hashlib.sha3_256(sharedInt.to_bytes(_DH_KEY_BYTES, "big")).digest()

def runMlKemExchange(verbose: bool = True):
    engine = MlKem768()
    keyPair = engine.generateKeyPair()
    encap = engine.encapsulate(keyPair.publicKey)
    recSecret = engine.decapsulate(encap.cipherText, keyPair.privateKey)

    if verbose:
        print(f"Engine              : {'native ML-KEM-768' if engine._useNative else 'classical fallback'}")
        print(f"Public key length  : {len(keyPair.publicKey)} bytes")
        print(f"Private key length : {len(keyPair.privateKey)} bytes")
        print(f"Ciphertext length  : {len(encap.cipherText)} bytes")
        print(f"Shared secret (hex): {encap.sharedSecret.hex()[:32]}...")
        print(f"Match verified     : {encap.sharedSecret == recSecret}")

    return keyPair, encap, recSecret

if __name__ == "__main__":
    runMlKemExchange(verbose=True)