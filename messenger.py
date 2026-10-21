import os
from crypto_utils import aes_cbc_encrypt, aes_cbc_decrypt, compute_hmac, verify_hmac
from rsa_utils import rsa_chiffrer_cle, rsa_dechiffrer_cle, generer_paire_rsa


def send_message(plaintext: str, rsa_public_key, verbose: bool = True) -> dict:

    """
    Chiffre un message destiné à Enzo avec le protocole hybride.
    > Retourne un dictionnaire avec tous les champs en hexadécimal.
    """

    if verbose:
        print("\n--- [ENRIK : DÉBUT DU CHIFFREMENT] ---")

    aes_key = os.urandom(32)    # clé AES aléatoire (32 octtes)
    hmac_key = os.urandom(32)   # clé HMAC aléatoire (32 octets)

    cles_combinees = aes_key + hmac_key     # on combine la clé AES + la clé HMAC 
    if verbose:
        print(f"\n[1] Clés de session éphémères générées (256 bits chacune) :")
        print(f"    - Clé symétrique AES  : {aes_key.hex()[:16]}... (sert au chiffrement du texte)")
        print(f"    - Clé secrète HMAC    : {hmac_key.hex()[:16]}... (sert au scellement d'intégrité)")

    
    cles_chiffrees = rsa_chiffrer_cle(cles_combinees, rsa_public_key)   # on chiffre en RSA la clé AES + la clé HMAC + la clé RSA publique)
    if verbose:
        print(f"\n[2] Chiffrement asymétrique RSA (OAEP-SHA256) :")
        print(f"    - Les 64 octets (AES + HMAC) sont chiffrés avec la clé publique RSA d'Enzo.")
        print(f"    - Bloc RSA obtenu : {cles_chiffrees.hex()[:24]}... ({len(cles_chiffrees)} octets)")

    plaintext_bytes = plaintext.encode("utf-8")     # encode en octets du texte brut, car AES ne fonctionne qu'avec des octets
    iv, ciphertext = aes_cbc_encrypt(plaintext_bytes, aes_key)      # on chiffre le texte en octet du message en AES et on récupère l'IV et le message chiffré
    if verbose:
        print(f"\n[3] Chiffrement symétrique AES-256-CBC :")
        print(f"    - IV (Vecteur d'Initialisation) : {iv.hex()} ({len(iv)} octets aléatoires).")
        print(f"      -> Rôle de l'IV : rend chaque message chiffré unique, même si le texte clair est identique.")
        print(f"    - Ciphertext produit : {ciphertext.hex()[:24]}... ({len(ciphertext)} octets, padding PKCS#7 inclus).")

    donnees_a_signer = iv + ciphertext      # on compacte les données chiffrées avec l'IV
    signature_hmac = compute_hmac(hmac_key, donnees_a_signer)   # on signe ces données avec le HMAC pour l'intégrité
    if verbose:
        print(f"\n[4] Calcul du HMAC-SHA256 (Schéma Encrypt-then-MAC) :")
        print(f"    - L'empreinte est calculée sur (IV + Ciphertext) avec la clé HMAC secrète.")
        print(f"    - HMAC produit : {signature_hmac.hex()} (32 octets).")
        print(f"      -> Rôle du HMAC : garantir qu'aucun bit de l'IV ou du chiffré n'a été altéré.")
        
    paquet = {
            "cles_chiffrees": cles_chiffrees.hex(),
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "hmac": signature_hmac.hex()
        }
    if verbose:
            print("\n[5] Paquet final assemblé en chaînes hexadécimales, prêt pour l'envoi réseau.\n")

    return paquet

def receive_message(packet: dict, rsa_private_key, verbose: bool = True) -> str:

    """
    Traite un paquet reçu, valide son intégrité et restitue le texte en clair.
    Lève une exception si le HMAC est invalide.
    """
    
    if verbose:
        print("\n--- [ENZO : RÉCEPTION ET DÉCHIFFREMENT] ---")

    cles_chiffrees = bytes.fromhex(packet["cles_chiffrees"])    # récupère le bloc RSA chiffré sous forme d'octets (via fromhex)
    iv = bytes.fromhex(packet["iv"])    # on reconstruit l'IV de 16 octets nécessaire au mode CBC
    ciphertext = bytes.fromhex(packet["ciphertext"])    # on refait les octets du message chiffré par AE
    mac_recu = bytes.fromhex(packet["hmac"])    # on récupère l'empreinte HMAC en octets aussi

    if verbose:
        print("\n[1] Paquet hexadécimal converti en octets bruts :")
        print(f"    - Bloc RSA reçu : {cles_chiffrees.hex()[:20]}...")
        print(f"    - IV reçu       : {iv.hex()}")
        print(f"    - Ciphertext    : {ciphertext.hex()[:20]}...")
        print(f"    - HMAC reçu     : {mac_recu.hex()[:20]}...")

    cles_combinees = rsa_dechiffrer_cle(cles_chiffrees, rsa_private_key)

    aes_key = cles_combinees[:32]   # Les octets d'indice 0 à 31 correspondent à la clé symétrique AES-256
    hmac_key = cles_combinees[32:]  # Les octets d'indice 32 à 63 correspondent à la clé secrète du HMAC
    
    if verbose:
        print("\n[2] Déchiffrement asymétrique RSA (avec la clé privée d'Enzo) :")
        print(f"    - Clé AES récupérée  : {aes_key.hex()[:16]}...")
        print(f"    - Clé HMAC récupérée : {hmac_key.hex()[:16]}...")

    donnees_recues = iv + ciphertext

    if verbose:
        print("\n[3] Contrôle d'intégrité et d'authenticité (HMAC) :")
        print("    - Recalcul du HMAC sur (IV + Ciphertext) reçu avec la clé HMAC extraite...")
        
    if not verify_hmac(hmac_key, donnees_recues, mac_recu):     # CRITIQUE : vérification du HMAC via le fonction (surtout pas comparaison avec '==')
        raise ValueError("Alerte intégrité : HMAC invalide")

    if verbose:
        print("    -> Succès : HMAC valide (comparaison en temps constant compare_digest).")
        print("    -> L'intégrité est certifiée : on autorise le déchiffrement AES.")

    plaintext_bytes = aes_cbc_decrypt(iv, ciphertext, aes_key)      # déchiffrement AES
    message_clair = plaintext_bytes.decode("utf-8")

    if verbose:
        print(f"\n[4] Déchiffrement symétrique AES-256-CBC :")
        print(f"    - Déchiffrement du bloc avec la clé AES et l'IV.")
        print(f"    - Suppression du padding PKCS#7 et conversion UTF-8.")
        print(f"    -> Message restitué : « {message_clair} »\n")

    return message_clair