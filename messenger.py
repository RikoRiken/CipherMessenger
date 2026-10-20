import os
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, compute_hmac, verify_hmac
from rsa_utils import rsa_chiffrer_cle, rsa_dechiffrer_cle, generer_paire_rsa


def send_message(plaintext: str, rsa_public_key) -> dict:

    """
    Chiffre un message destiné à Enzo avec le protocole hybride.
    > Retourne un dictionnaire avec tous les champs en hexadécimal.
    """

    aes_key = os.urandom(32)    # clé AES aléatoire (32 octtes)
    hmac_key = os.urandom(32)   # clé HMAC aléatoire (32 octets)

    cles_combinees = aes_key + hmac_key     # on combine la clé AES + la clé HMAC 
    cles_chiffrees = rsa_chiffrer_cle(cles_combinees, rsa_public_key)   # on chiffre en RSA la clé AES + la clé HMAC + la clé RSA publique)

    plaintext_bytes = plaintext.encode("utf-8")     # encode en octets du texte brut, car AES ne fonctionne qu'avec des octets
    iv, ciphertext = aes_cbc_encrypt(plaintext_bytes, aes_key)      # on chiffre le texte en octet du message en AES et on récupère l'IV et le message chiffré

    donnees_a_signer = iv + ciphertext      # on compacte les données chiffrées avec l'IV
    signature_hmac = compute_hmac(hmac_key, donnees_a_signer)   # on signe ces données avec le HMAC pour l'intégrité

    return {
        "cles_chiffrees": cles_chiffrees.hex(),
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac": signature_hmac.hex()
    }   # construction du "paquet" à envoyer, en convertissant tout en hexa


def receive_message(packet: dict, rsa_private_key) -> str:

    """
    Traite un paquet reçu, valide son intégrité et restitue le texte en clair.
    Lève une exception si le HMAC est invalide.
    """

    cles_chiffrees = bytes.fromhex(packet["cles_chiffrees"])    # récupère le bloc RSA chiffré sous forme d'octets (via fromhex)
    iv = bytes.fromhex(packet["iv"])    # on reconstruit l'IV de 16 octets nécessaire au mode CBC
    ciphertext = bytes.fromhex(packet["ciphertext"])    # on refait les octets du message chiffré par AE
    mac_recu = bytes.fromhex(packet["hmac"])    # on récupère l'empreinte HMAC en octets aussi

    cles_combinees = rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key)

    aes_key = cles_combinees[:32]   # Les octets d'indice 0 à 31 correspondent à la clé symétrique AES-256
    hmac_key = cles_combinees[32:]  # Les octets d'indice 32 à 63 correspondent à la clé secrète du HMAC

    donnees_recues = iv + ciphertext
    if not verify_hmac(hmac_key, donnees_recues, mac_recu):     # CRITIQUE : vérification du HMAC via le fonction (surtout pas comparaison avec '==')
        raise ValueError("Alerte intégrité : HMAC invalide")

    plaintext_bytes = aes_cbc_decrypt(iv, ciphertext, aes_key)      # déchiffrement AES
    return plaintext_bytes.decode("utf-8")      # conversion des ocets en texte clair