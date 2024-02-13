"""
Vous ne devriez pas avoir besoin de modifier ce fichier.

Note : À la correction, nous remplacerons le fichier test_lamport.py
par une autre version contenant plus de tests. Toutes les modifications
appliquées dans ce fichier seront ainsi perdues.
"""

from tp1.lamport import Message, Lamport


class TestLamport:
    def test_good_sig(self):
        """
        Signe et vérifie pour s'assurer que tout fonctionne.
        """
        # Génération d'un message (hachage de "Bon").
        msg = Message.from_str("Bon")

        # Génération des clés.
        sk, pk = Lamport.generate_keys()

        # Signature du message.
        sig = Lamport.sign(msg, sk)

        # Vérification de la signature.
        worked = Lamport.verify(msg, pk, sig)
        assert worked

    def test_bad_sig(self):
        """
        Signe, mais modifie ensuite la signature en hachant l'un des blocs qu'il contient.
        Cela devrait casser la signature avec une grande probabilité.
        Ce test essaie également d'appliquer la signature à un message complètement différent.
        """
        # Génération d'un message (hachage de "Mauvais").
        msg = Message.from_str("Mauvais")

        # Génération des clés.
        sk, pk = Lamport.generate_keys()

        # Signature du message.
        sig = Lamport.sign(msg, sk)

        # Modification de la signature.
        # Le hachage d'une partie devrait la casser sauf avec 2^-256 chances.
        sig.preimage[16].data = sig.preimage[26].hash_data()

        # Vérification de la signature.
        worked = Lamport.verify(msg, pk, sig)
        assert not worked

        # Essai avec un message complètement différent.
        msg = Message.from_str("Pire")
        worked = Lamport.verify(msg, pk, sig)
        assert not worked

    def test_good_many(self):
        """
        Teste 1000 signatures qui devraient toutes fonctionner.
        """
        for i in range(1000):
            s = f"Bon {i}"
            msg = Message.from_str(s)

            # Génération des clés.
            sk, pk = Lamport.generate_keys()

            # Signature du message.
            sig = Lamport.sign(msg, sk)

            # Vérification de la signature.
            worked = Lamport.verify(msg, pk, sig)
            assert worked

    def test_bad_many(self):
        """
        Teste 1000 signatures, les modifiant toutes pour qu'elles échouent.
        """
        for i in range(1000):
            s = f"Mauvais {i}"
            msg = Message.from_str(s)

            # Génération des clés.
            sk, pk = Lamport.generate_keys()

            # Signature du message.
            sig = Lamport.sign(msg, sk)
            sig.preimage[i % 8].data = sig.preimage[i % 9].hash_data()

            # Vérification de la signature.
            worked = Lamport.verify(msg, pk, sig)
            assert not worked
