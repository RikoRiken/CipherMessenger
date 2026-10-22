# ===> A PARTIR D'ICI, FONCTIONS POUR MESSAGERIE VIA LINUX TCP SOCKET EN LOCAL <=== 

import json

def send_packet(sock, data: dict):  # sock = objet connecté entre les deux terminaux. data = dict envoyé par send_message dans messenger.py

    """Sérialise un dictionnaire en JSON sur une ligne unique terminée par \\n."""

    trame = json.dumps(data) + "\n"     # on créé une trame json depuis les données en octets, puis on rajoute un saut de ligne à la fin
    sock.sendall(trame.encode("utf-8"))     # on envoi la trame (avec saut ligne à la fin) en octets (d'ou le encode utf8) via le socket tcp


def recv_packet(sock):

    """Lit une ligne complète jusqu'au \\n et reconstitue le dictionnaire."""

    flux = sock.makefile("r", encoding="utf-8")    # transforme le flux brut en flux fichier texte en lecture
    ligne = flux.readline()     # attends et lit les données du flux (en attendant le saut de ligne \n)
    if not ligne:   
        return None
    return json.loads(ligne.strip())    # retire le '\n' et désérialise le JSON pour reconstituer le dictionnaire Python (les données)