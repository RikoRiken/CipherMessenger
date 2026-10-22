import socket
from rsa_utils import charger_cle_publique_pem
from messenger import send_message
from network_utils import send_packet, recv_packet

choix = input("Activer les explications détaillées ? [Y/n] : ").strip().lower()
VERBOSE = choix not in ("n", "no")

HOST = "127.0.0.1"
PORT = 5000

BANNIERE = r"""
    ______                            __           __
   / ____/___  ____________  ______  / /____  ____/ /
  / __/ / __ \/ ___/ ___/ / / / __ \/ __/ _ \/ __  / 
 / /___/ / / / /__/ /  / /_/ / /_/ / /_/  __/ /_/ /  
/_____/_/ /_/\___/_/   \__, / .___/\__/\___/\__,_/   
   _________          /____/_/                       
  / ____/ (_)__  ____  / /_                          
 / /   / / / _ \/ __ \/ __/                          
/ /___/ / /  __/ / / / /_                            
\____/_/_/\___/_/ /_/\__/                                                                                                                                                                                                    
"""

print(BANNIERE)

socket_reseau = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_reseau.connect((HOST, PORT))
print(f"[RÉSEAU] Connecté à Enzo sur {HOST}:{PORT}")

reponse = recv_packet(socket_reseau)
if not reponse or reponse.get("type") != "handshake":
    raise ConnectionError("Échec du handshake.")

if VERBOSE:
    print("\n[PEM] Réception de la clé publique d'Enzo en texte brut PEM.")
enzo_pub = charger_cle_publique_pem(reponse["cle_publique"].encode("utf-8"))
if VERBOSE:
    print("[RSA] Clé publique reconstruite en mémoire : Enrik peut chiffrer pour Enzo.")

try:
    while True:
        texte = input("\nEnrik > ")
        if not texte or texte.lower() in ("exit", "quit"):
            break

        paquet = send_message(texte, enzo_pub, verbose=VERBOSE)

        send_packet(socket_reseau, paquet)
        if VERBOSE:
            print("[RÉSEAU] Trame JSON expédiée sur le socket TCP.")

finally:
    socket_reseau.close()
    print("[RÉSEAU] Déconnexion.")