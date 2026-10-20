import os   # ici, nécessaire pour générer des octets aléatoires avec os.urandom() => principalement pour faire un IV
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes     # cipher c'est le moteur de calcul, algorithms contient AES, modes contient CBC
from cryptography.hazmat.primitives import padding, hashes      # fournit les outils de padding (padding PKCS#7) et les fonctions de hachage (hashes.SHA256 pour le HMAC)
from cryptography.hazmat.primitives import hmac as crypto_hmac      # permet de générer un HMAC en SHA-256, c'est un peu le moteur de calcul
import hmac     # nécessaire pour la fonction hmac.compare_digest(), pas compris dans le module 'cryptography' (pour ne pas utiliser hmac == hmac reçu)


def aes_cbc_encrypt(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes]:

    """
    Chiffre un message brut en AES-256-CBC avec un IV aléatoire et un padding PKCS#7.

    Entrées :
      - text (bytes/octets) : le texte en clair.
      - aes_key (bytes/octets) : clé secrète de 32 octets (256 bits).

    Sortie :
      - tuple (iv, ciphertext) : retourn le IV et le texte chiffré en bytes.
    """

    iv = os.urandom(16)     # génère un IV random de 16 octets, c'est la taille d'un bloc AES 

    padder = padding.PKCS7(128).padder()    # ajout padding de 128 bits (16 bytes) en PKCS#7 (norme en AES) => le .padder() prépare juste l'action, on configure pour qu'il fonctionne sur 16 octets
    padded_data = padder.update(plaintext) + padder.finalize()      # on prends le 'text' clair en entrée, on l'ajoute dans le bloc avec update(text) => padder.finalize regarde s'il manque des octets à la fin et complète

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))     # on fait la fiche technique : chiffrement avec AES, on donne la variable contenant clé AES, et on choisi le mode CBC qui utilisera la variable de l'IV aléatoire
    encryptor = cipher.encryptor()      # on récup la config passive 'cipher', et la fonction native 'encryptor' permet de stocker les blocs (c'est un objet natif de 'cryptography' qui fait les calculs en RAM) 
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()       # pour obtenir le texte chiffré, on utilise notre encryptor auquel on ajoute le texte AVEC padding. '.finalize sert à vérifier qu'il n'y a plus de blocs en attente

    return iv, ciphertext       # retourne dans le tuple : 1. le IV calculé et 2. le texte chiffré


def aes_cbc_decrypt(iv: bytes, ciphertext: bytes, aes_key: bytes) -> bytes:

    """
    Déchiffre un texte chiffré en AES-256-CBC (via aes_cbc_encrypt()), retire le padding et retourne le plaintext en octet.)
    """

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))     # comme pour encrypt, on définit la fiche technique exacte de ce qu'on utilise : AES avec aes_key, mode CBC avec l'IV...
    decryptor = cipher.decryptor()      # ici pour faire l'inverse, on utilise decryptor au lieu d'encryptor 
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()       # dans le flux, on update chaque bloc de 16bytes chiffré avec decryptor pour déchiffrer (1bloc par 1 jusqu'au finalize quand y'en a plus)


    unpadder = padding.PKCS7(128).unpadder()    # une fois tout déchiffré, on va définir le padding qui avait été utilisé pour l'encryption
    plaintext = unpadder.update(padded_data) + unpadder.finalize()      # ensuite on retire le padding qui avait été ajouté afin de récupérer juste le texte déchiffré

    return plaintext


def compute_hmac(hmac_key: bytes, data: bytes) -> bytes:

    """
    Calcule l'empreinte HMAC-SHA256 sur les données fournies (data).
    Retourne une empreinte SHA-256 de 32 octets calculés sur l'ensemble du texte chiffré reçu + l'IV qui est envoyé en clair.
    """

    h = crypto_hmac.HMAC(hmac_key, hashes.SHA256())     # On définit la fiche technique génère un hash SHA-256 à partir de la clé HMAC qu'on lui a fournit
    h.update(data)      # On donne les données à protéger, ici data qui contiendra IV + text chiffré (sur l'ensemble du texte final)
    return h.finalize()     # Une fois tous les update(data) finis, on renvoie l'empreinte SHA256


def verify_hmac(hmac_key: bytes, data: bytes, mac: bytes) -> bool:

    """
    Vérifie l'authenticité des données en comparant le HMAC. On va récupérer le HMAC envoyé 'mac'
    et recalculer le HMAC attendu avec 'expected_mac ='.
    On le compare bien avec 'compare_digest' et pas un simple '=='
    """

    expected_mac = compute_hmac(hmac_key, data)      # recalcule de l'empreinte des blocs à partir de la clé HMAC (qui est secrète)
    return hmac.compare_digest(expected_mac, mac)       # OBLIGATOIRE : protection contre les attaques on l'on devine le hmac en time-based (deviner les carac. un par un)