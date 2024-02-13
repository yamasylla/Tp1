"""
Travail Pratique 1 : Signatures basées sur le hachage

Le code présent dans ce module affiche actuellement à l'exécution des erreurs.
Vous devez remplacer les parties indiquant "Votre code ici" par votre implémentation
afin qu'il puisse s'exécuter correctement (sans aucune erreur).

Il peut également être utile de créer vos propres fonctions ou méthodes,
notamment dans le fichier tp1/forge.py.
"""

from tp1.forge import forge
from tp1.lamport import Lamport, Message


if __name__ == "__main__":
    # Définition du message.
    text_str = "Chaîne de blocs"
    print(text_str)

    # Conversion du message en bloc d'octets.
    message = Message.from_str(text_str)
    print(message.to_hex())

    # Génération de la paire de clés (secret key, public key).
    sk, pk = Lamport.generate_keys()

    # Affichage de la clé publique.
    pk_hex = pk.to_hex()
    print(f"Clé Publique : {pk_hex[:10]}...{pk_hex[-10:]}")

    # Signature du message.
    sig = Lamport.sign(message, sk)

    # Affichage de la signature.
    sig_hex = sig.to_hex()
    print(f"Signature : {sig_hex[:10]}...{sig_hex[-10:]}")

    # Vérification de la signature.
    worked = Lamport.verify(message, pk, sig)
    print(f"Vérification de la signature : {'BONNE' if worked else 'MAUVAISE'}")

    # Falsification d'une signature.
    forged_msg, forged_sig = forge()
    forged_sig_hex = forged_sig.to_hex()
    print(f"Message falsifié : '{forged_msg}'")
    print(f"Signature falsifiée : {forged_sig_hex[:10]}...{forged_sig_hex[-10:]}")
