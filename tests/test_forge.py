"""
TestForgery.test_forgery() teste la fonction forge() pour voir si elle produit une signature
valide à partir de la clé publique `hex_pub_key` codée en dur.
Si ce test réussit avec les autres tests, cela signifie que la falsification a fonctionné.
"""

from tp1.lamport import Lamport, Message, PublicKey
from tp1.signatures import hex_pub_key
from tp1.forge import forge


class TestForgery:
    def test_forgery(self):
        # Obtention de la clé publique.
        pk = PublicKey.from_hex(hex_pub_key)

        # Notez que ce test appelle la fonction forge(), ce qui peut prendre un certain temps.
        # Une façon de rendre cela beaucoup plus rapide est qu'une fois que vous avez réussi
        # à contrefaire une signature, vous pouvez modifier le code dans forge() pour qu'il démarre
        # juste avant qu'il n'atteigne la falsification, de sorte que l'exécution de forge() soit très rapide.
        # Le fait que vous sachiez commencer à environ 15 000 comme nombre d'itérations
        # est une bonne preuve que vous avez déjà fait le travail du processeur auparavant.
        forged_string, forged_sig = forge()

        # Assurez-vous que le message pour la signature falsifiée contient le mot "contrefait".
        # Cela garantit qu'il est différent des 5 messages signés fournis.
        # Il devrait également contenir votre adresse e-mail U-LAVAL, mais nous ne le vérifions pas ici.
        assert "contrefait" in forged_string

        # Affichage du message falsifié.
        print(f"Message falsifié : '{forged_string}'")
        print(f"Message falsifié contient la sous-chaîne 'contrefait'? OUI.")

        # Vérification de la signature.
        forged_msg = Message.from_str(forged_string)
        worked = Lamport.verify(forged_msg, pk, forged_sig)
        assert worked
