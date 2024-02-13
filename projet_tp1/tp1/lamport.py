"""
Travail Pratique 1 : Signatures basées sur le hachage

Dans ce module, vous implémenterez un système de signature basé sur le hachage.
Nous utiliserons sha256 comme fonction de hachage ainsi que le schéma de signature de Lamport.

Si vous exécutez `pytest -vv` et que tout réussit, cela signifie que votre implémentation
semble bonne.

Il y a probablement un moyen de faire passer les tests sans rajouter une implémentation de signature réelle, mais
je pense qu'il serait à votre avantage de penser à compléter le code correctement :).
"""

from typing import Self

import hashlib
import secrets
import sys


class Block:
    """
    Un bloc de données a toujours une longueur de 32 octets.
    Nous utilisons sha256 et c'est la taille à la fois de la sortie (définie par la fonction de hachage)
    et de nos entrées.
    """

    def __init__(self, data=None):
        self.data = data

    def hash_data(self) -> bytes:
        """
        Retourne le hachage sha256 des données du bloc.
        """
        assert not self.is_empty()
        return hashlib.sha256(self.data).digest()

    def is_preimage(self, arg: bytes) -> bool:
        """
        Retourne True si le bloc est une pré-image de l'argument.
        Par exemple, si Y = hash(X), alors X.is_preimage(Y) renverra True,
        et Y.is_preimage(X) renverra False.
        """
        return not self.is_empty() and secrets.compare_digest(self.hash_data(), arg)

    def is_empty(self) -> bool:
        """
        Retourne True si le bloc n'a pas de données et False sinon.
        """
        return self.data is None

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        Retourne un objet Block à partir d'une séquence d'octets de longueur variable.
        """
        return cls(data)

    def to_hex(self) -> str:
        """
        Retourne une chaîne codée en hexadécimal des données du bloc.
        """
        assert not self.is_empty()
        return self.data.hex()


class Message(Block):
    """
    Un message à signer n'est rien d'autre qu'un bloc.
    """

    @classmethod
    def from_str(cls, s: str) -> Self:
        """
        Retourne un objet Message dont la donnée est le hash de la chaîne
        fournie en argument.
        """
        return cls(hashlib.sha256(s.encode()).digest())


class SecretKey:
    def __init__(self):
        self.zero_pre = [Block() for _ in range(256)]
        self.one_pre = [Block() for _ in range(256)]


class PublicKey:
    def __init__(self):
        self.zero_hash = [Block() for _ in range(256)]
        self.one_hash = [Block() for _ in range(256)]

    @classmethod
    def from_hex(cls, s: str) -> Self:
        """
        Prend une chaîne de PublicKey.to_hex() et la transforme en un objet PublicKey.
        Renverra une erreur s'il y a des caractères non hexadécimaux ou si la longueur est incorrecte.
        """
        pk = cls()

        # Un octet de 8 bits peut avoir des valeurs allant de 00000000 à
        # 11111111 sous forme binaire, qui peuvent être commodément
        # représentées par 00 à FF en hexadécimal.
        # Ce qui veut dire que 32 octets = 32 * 2 = 64 caractères hexadécimaux.
        # 256 blocs, 2 rangées, 64 caractères hexadécimaux par bloc.
        expected_length = 256 * 2 * 64

        # Nous nous assurons que la chaîne hexadécimale est de la bonne longueur.
        if len(s) != expected_length:
            raise ValueError(
                f"Clé publique de longueur {len(s)}, au lieu de {expected_length}."
            )

        # Conversion hexadécimal -> bytes
        buffer = bytes.fromhex(s)

        for i in range(256):
            pk.zero_hash[i] = Block.from_bytes(buffer[32 * i : 32 * (i + 1)])

        for i in range(256, 512):
            pk.one_hash[i - 256] = Block.from_bytes(buffer[32 * i : 32 * (i + 1)])

        return pk

    def to_hex(self) -> str:
        """
        Retourne une chaîne hexadécimale d'une clé publique.
        """
        s0 = "".join(block.to_hex() for block in self.zero_hash)
        s1 = "".join(block.to_hex() for block in self.one_hash)

        return s0 + s1


class Sig:
    """
    Une signature se compose de 256 blocs de 32 octets chacun.
    C'est une révélation sélective de la clé privée, selon les bits du message.
    """

    def __init__(self):
        self.preimage = [Block() for _ in range(256)]

    @classmethod
    def from_hex(cls, s: str) -> Self:
        """
        Même idée que PublicKey.from_hex, mais deux fois moins grand.
        Le format est juste chaque bloc de la signature dans l'ordre.
        """
        sig = cls()

        # Un octet de 8 bits peut avoir des valeurs allant de 00000000 à
        # 11111111 sous forme binaire, qui peuvent être commodément
        # représentées par 00 à FF en hexadécimal.
        # Ce qui veut dire que 32 octets = 32 * 2 = 64 caractères hexadécimaux.
        # 256 blocs, 1 rangée, 64 caractères hexadécimaux par bloc.
        expected_length = 256 * 1 * 64

        # Nous nous assurons que la chaîne hexadécimale est de la bonne longueur.
        if len(s) != expected_length:
            raise ValueError(
                f"Clé publique de longueur {len(s)}, au lieu de {expected_length}."
            )

        # Conversion hexadécimal -> bytes
        buffer = bytes.fromhex(s)

        for i in range(256):
            sig.preimage[i] = Block.from_bytes(buffer[32 * i : 32 * (i + 1)])

        return sig

    def to_hex(self) -> str:
        """
        Retourne une chaîne hexadécimale d'une signature.
        """
        return "".join(block.to_hex() for block in self.preimage)


class Lamport:
    @classmethod
    def generate_keys(cls) -> tuple[SecretKey, PublicKey]:
        sk = SecretKey()
        pk = PublicKey()

        for i in range(256):
            sk.zero_pre[i] = secrets.token_bytes(32)
            sk.one_pre[i] = secrets.token_bytes(32)

            pk.zero_hash[i] = hashlib.sha256(sk.zero_pre[i]).digest()
            pk.one_hash[i] = hashlib.sha256(sk.one_pre[i]).digest()

        return sk, pk

    @classmethod
    def sign(cls, msg: Message, sk: SecretKey) -> Sig:
        sig = Sig()

        hash_data = msg.hash_data()
        for i in range(256):
            b = hash_data[i // 8] >> (7 - (i % 8)) & 1
            if b == 0:
                sig.preimage[i] = sk.zero_pre[i]
            else:
                sig.preimage[i] = sk.one_pre[i]

        return sig

    @classmethod
    def verify(cls, msg: Message, pk: PublicKey, sig: Sig) -> bool:
        hash_data = msg.hash_data()
        for i in range(256):
            b = hash_data[i // 8] >> (7 - (i % 8)) & 1
            if hashlib.sha256(sig.preimage[i]).digest() != pk.zero_hash[i] and b == 0:
                return False
            if hashlib.sha256(sig.preimage[i]).digest() != pk.one_hash[i] and b == 1:
                return False
        return True


if __name__ == "__main__":
    hash_size_in_bytes = hashlib.sha256().digest_size

    # 256 blocs de 32 octets chacun, 2 rangées.
    key_size_in_bytes = 256 * hashlib.sha256().digest_size * 2

    # 256 blocs de 32 octets chacun, 1 rangée.
    sig_size_in_bytes = 256 * hashlib.sha256().digest_size * 1

    table_headers = "Hash (octets) | Clé publique / Clé privée (Ko) | Signature (Ko)"
    print("-" * len(table_headers))
    print(table_headers)
    print("-" * len(table_headers))
    print(
        f"{hash_size_in_bytes:^14}|"
        f"{key_size_in_bytes // 1000:^32}|"
        f"{sig_size_in_bytes // 1000:^15}"
    )
    print("-" * len(table_headers))
