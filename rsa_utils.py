from cryptography.hazmat.primitives.asymmetric import rsa, padding      # rsa est nécessaire pour faire le chiffrement, et padding pour créer le padding OAEP
from cryptography.hazmat.primitives import hashes       # utilisé pour le chiffrement et déchiffrement de clé RSA (pour OAEP / padding)


def generer_paire_rsa():

    """
    Génère une paire de clés ASYMETRIQUE RSA-2048.
    Retourne le tuple (private_key, public_key).
    """

    private_key = rsa.generate_private_key(     # Génération d'une clé privée RSA : 
        public_exponent=65537,      # la norme pour l'exposant est 65537
        key_size=2048       # on définit la taille à 2048 bits (d'ou le rsa-2048)
    )   
        
    public_key = private_key.public_key()     # dérivation clé publique à partir de la clé privée

    return private_key, public_key


def rsa_chiffrer_cle(cles: bytes, rsa_public_key) -> bytes:

    """
    Chiffre les clés symétriques (64 octets : AES + HMAC) avec la clé publique de Bob.
    Utilise le bourrage OAEP avec SHA-256.
    """

    cles_chiffrees = rsa_public_key.encrypt(
        cles,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),    # MGF1 (Mask Generation Function) est l'algorithme qui génère le masque aléatoire
            algorithm=hashes.SHA256(),     # 
            label=None      # Pas de label spécifique nécessaire ici
        )
    )
    return cles_chiffrees


def rsa_dechiffrer_cle(cles_chiffrees: bytes, rsa_private_key) -> bytes:

    """
    Déchiffre les clés symétriques reçues avec la clé privée de Bob.
    Utilise la même configuration OAEP que pour le chiffrement.
    """

    cles_dechiffrees = rsa_private_key.decrypt(
        cles_chiffrees,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cles_dechiffrees


# ===> A PARTIR D'ICI, FONCTIONS POUR MESSAGERIE VIA LINUX TCP SOCKET EN LOCAL <=== 

from cryptography.hazmat.primitives import serialization

def exporter_cle_publique_pem(public_key):

    """ on convertit l'objet 'public_key' qu'on a généré avec 'generer_paire_rsa'
    en octets (TCP n'accepte que des octets) pour la convertir en format .pem 
    et l'envoyer plus facilement sans erreurs.
    """

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,    # on sérialise (obligatoire) et encode en base64 pour le fichier .pem
        format=serialization.PublicFormat.SubjectPublicKeyInfo     # on décrit le bon format pour la clé publique, ici la norme ASN1
    )


def charger_cle_publique_pem(pem_bytes: bytes):

    """Reconstitue un objet clé publique RSA depuis des octets PEM."""

    return serialization.load_pem_public_key(pem_bytes)    # fonction de lib cryptogaphy qui permet de recréer le fichier pem depuis les octets reçu en TCP