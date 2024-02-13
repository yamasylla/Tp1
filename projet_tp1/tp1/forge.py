"""
Travail Pratique 1 : Signatures basées sur le hachage

Remarque concernant les clés et signatures fournies :
La clé publique, les signatures fournies, ainsi que les méthodes "from_hex" peuvent ne pas fonctionner avec toutes les
différentes implémentations que vous créerez. Plus précisément, elles sont liées à un boutisme:
https://fr.wikipedia.org/wiki/Boutisme.

Si, par exemple, vous avez décidé d'encoder vos clés publiques (selon le modèle dans les diapositives) de haut en bas,
puis de gauche à droite :
<bit 0, ligne 0> <bit 0, ligne 1> <bit 1, ligne 0> <bit 1, ligne 1> ... 
alors cela ne fonctionnera pas avec la clé publique fournie ici, car elle a été encodée comme :
<bit 0, ligne 0> <bit 1, ligne 0> <bit 2, ligne 0> ... <bit 255, ligne 0> <bit 0, ligne 1> ...
(de gauche à droite, puis de haut en bas).

Alors, bien qu'en classe, j'ai dit que toutes les décisions comme celle-ci fonctionneraient tant qu'elles étaient
cohérentes... ce n'est pas vraiment le cas ! Parce que vos méthodes devront utiliser le même ordre que celles que j'ai
écrites afin de créer les signatures ici. J'ai utilisé ce que je pensais être l'encodage le plus direct/le plus simple,
mais le choix du boutisme est semblable au choix entre les tabulations et les espaces pour l'indentation :).

Donc, pour plus de clarté et puisque ce n'est pas si évident d'après les méthodes de décodage from_hex, voici
l'ordre utilisé :

Clés secrètes et Clés publiques :
Les 256 éléments de la ligne 0, du bit le plus significatif au bit le moins significatif (l'orientation gros-boutiste)
suivis des 256 éléments de la ligne 1. Total de 512 blocs de 32 octets chacun, pour 16384 octets.
Pour une vérification efficace d'un bit dans un tableau de 32 octets en utilisant cette orientation,
vous pouvez utiliser:
    arr[i // 8] >> (7 - (i % 8)) & 1
où arr[] est le tableau d'octets et i est le numéro de bit ; i=0 est le plus à gauche et i=255 est le plus à droite.
L'instruction ci-dessus renverra un 1 ou un 0 en fonction de ce qui se trouve à cet emplacement de bit.

Messages : les messages sont encodés de la même manière que les sorties de la fonction de hachage sha256, donc rien
à choisir ici.

Signatures : Les signatures sont également lues de gauche à droite, du bit le plus significatif au bit le moins
significatif, avec 256 blocs de 32 octets chacun, pour un total de 8192 octets. Rien n'indique si la pré-image fournie
provient de la rangée 0 ou de la rangée 1. Le hachage de message qui l'accompagne peut être utilisé à la place
ou les deux peuvent être essayés. Cela interprète également le hachage du message selon l'orientation gros-boutiste où:
    message[i // 8] >> (7 - (i % 8)) & 1
peut être utilisé pour déterminer quel bloc de pré-image révéler, où message[] est le message à signer, et i est
la séquence de bits dans le message et les blocs dans la signature.

Espérons que vous n'ayez pas de problèmes avec différents schémas d'encodage. Si vous voulez vraiment utiliser votre
propre méthode que vous trouvez plus facile à utiliser ou plus intuitive, c'est OK ! Vous devrez encoder à nouveau
la clé et les signatures fournies dans `signatures.py` pour correspondre à votre orientation afin qu'elles soient des
signatures valides avec votre système. Cependant, cela demandera probablement plus de travail.
Je vous recommanderai donc d'utiliser l'encodage gros-boutiste décrit ici.

forge() est la fonction de falsification de signature que vous devrez compléter. Il s'agit d'une partie fun
du TP1 qui nécessitera que votre ordinateur roule pendant un certain nombre de minutes.

La fonction forge() ne prend aucun argument. Les entrées sont toutes codées en dur dans la fonction, ce qui est un
peu moche, mais fonctionne bien pour nos besoins. La clé publique et les signatures sont fournies dans le fichier
`signatures.py` et le code pour les convertir dans les structures de données appropriées est déjà rempli.

Votre travail consistera à faire en sorte que cette fonction retourne deux choses : une chaîne contenant la sous-chaîne
"contrefait" ainsi que votre adresse e-mail U-LAVAL, et une signature valide sur le hachage de ce message sous forme de
chaîne de caractères, à partir de la clé publique fournie dans le fichier signatures.py.

La fonction forge est testée par TestForgery.test_forgery() dans le fichier tests/test_forge.py. Si vous exécutez
donc la commande `pytest -vv` et que tout passe, cela signifie que votre implémentation semble être bonne.
"""

from tp1 import signatures
from tp1.lamport import Lamport, Message, PublicKey, Sig


def forge() -> tuple[str, Sig]:
    """
    Retourne un tuple composé d'un message sous forme de chaîne de caractères
    et une signature valide sur le hachage de ce message à partir de la clé publique
    fournie dans le fichier signatures.py.
    """
    # Décodage de la clé publique et des 5 signatures en
    # structures utilisables à partir des chaînes hexadécimales.
    pk = PublicKey.from_hex(signatures.hex_pub_key)
    sig_1 = Sig.from_hex(signatures.hex_sig_1)
    sig_2 = Sig.from_hex(signatures.hex_sig_2)
    sig_3 = Sig.from_hex(signatures.hex_sig_3)
    sig_4 = Sig.from_hex(signatures.hex_sig_4)
    sig_5 = Sig.from_hex(signatures.hex_sig_5)

    print(
        f"Sig 1 : {'BONNE' if Lamport.verify(Message.from_str('1'), pk, sig_1) else 'MAUVAISE'}"
    )
    print(
        f"Sig 2 : {'BONNE' if Lamport.verify(Message.from_str('2'), pk, sig_2) else 'MAUVAISE'}"
    )
    print(
        f"Sig 3 : {'BONNE' if Lamport.verify(Message.from_str('3'), pk, sig_3) else 'MAUVAISE'}"
    )
    print(
        f"Sig 4 : {'BONNE' if Lamport.verify(Message.from_str('4'), pk, sig_4) else 'MAUVAISE'}"
    )
    print(
        f"Sig 5 : {'BONNE' if Lamport.verify(Message.from_str('5'), pk, sig_5) else 'MAUVAISE'}"
    )

    msg_str = "Mon message contrefait"

    # -----
    # TODO: Votre code ici...
    # ----
    # Astuce: msg.data[i // 8] >> (7 - (i % 8)) & 1


if __name__ == "__main__":
    forge()
