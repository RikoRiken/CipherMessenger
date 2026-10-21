import socket
from rsa_utils import generer_paire_rsa, exporter_cle_publique_pem
from messenger import receive_message
from network_utils import send_packet, recv_packet

choix = input("Activer les explications détaillées ? [Y/n] : ").strip().lower()
VERBOSE = choix not in ("n", "no")

HOST = "127.0.0.1"
PORT = 5000

print(f"\n=== [DÉMARRAGE DU DESTINATAIRE : ENZO] ===")

if VERBOSE:
    print("\n[RSA] Génération des deux clés RSA (2048 bits)...")

enzo_priv, enzo_pub = generer_paire_rsa()
if VERBOSE:
    print(" -> Clé PRIVEE créée : conservée secrètement en mémoire.")
    print(" -> Clé PUBLIQUE créée : composée du module n et de l'exposant public e.")

pem_bytes = exporter_cle_publique_pem(enzo_pub)
if VERBOSE:
    print("\n[PEM] Exportation de la clé publique au format standard PEM :")
    print(f" -> Format texte encodé en Base64 encadré par des balises d'en-tête.\n")
    print(pem_bytes.decode("utf-8").strip())

socket_serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_serveur.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
socket_serveur.bind((HOST, PORT))
socket_serveur.listen(1)
print(f"\n[RÉSEAU] En attente de connexion sur {HOST}:{PORT}...")

socket_reseau, adresse = socket_serveur.accept()
print(f"[RÉSEAU] Enrik connecté depuis {adresse}")

try:
    send_packet(
        socket_reseau,
        {"type": "handshake", "cle_publique": pem_bytes.decode("utf-8")},
    )
    if VERBOSE:
        print("\n[HANDSHAKE] Clé publique PEM transmise à Enrik sur le canal TCP.")

    while True:
        paquet = recv_packet(socket_reseau)
        if paquet is None:
            print("\n[RÉSEAU] Enrik s'est déconnecté.")
            break

        try:
            message_clair = receive_message(paquet, enzo_priv, verbose=VERBOSE)
            print(f">>> Message affiché pour Enzo : {message_clair}")
        except ValueError as err:
            print(f"\n[ALERTE] Paquet rejeté sans déchiffrement AES : {err}")

finally:
    socket_reseau.close()
    socket_serveur.close()