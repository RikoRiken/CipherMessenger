# Messagerie Hybride Sécurisée | Enrik & Enzo

* **Auteurs :** Enrik DOLLE & Enzo BOURGOIN
* **Cours :** Fondamentaux de la cryptographie — Master 1 (spé. Offensif/Défensif)

</br>

## 1. Vue d'ensemble du protocole

Cette application implémente un système de messagerie sécurisé de bout en bout en console entre deux terminaux indépendants (local) :
* **Enzo (Serveur TCP) :** détient une paire de clés asymétriques RSA et reçoit les messages.
* **Enrik (Client TCP) :** récupère l'identité publique d'Enzo et chiffre les messages via un schéma hybride.

### Choix retenues dans le cadre du projet

| Rôle | Algorithme | Justification technique |
| :--- | :--- | :--- |
| **Chiffrement des données** | **AES-256-CBC** | Standard symétrique robuste. Padding PKCS#7. |
| **Unicité des messages** | **IV aléatoire (16 octets)** | Tirage d'une suite aléatoire (`os.urandom`) pour éviter qu'un même texte produise un même chiffré. |
| **Échange de clés** | **RSA-OAEP-SHA256 (2048 bits)** | Chiffre la combinaison des clés de session (`AES` + `HMAC`). |
| **Intégrité et authenticité** | **HMAC-SHA256** | Schéma *Encrypt-then-MAC* appliqué sur `IV + ciphertext`. |
| **Format des clés** | **PEM / PKCS#8** | Standard ouvert garantissant l'interopérabilité (encodage Base64 structuré, type clé SSH). |

</br>

## 2. Architecture du code

```text
├── crypto_utils.py     # Logique chiffrement symétriques (AES-CBC, padding, HMAC)
├── rsa_utils.py        # Logique chiffrement asymétriques (génération RSA, OAEP, clés PEM)
├── messenger.py        # Logique de l'application de messagerie (send_message, receive_message)
├── network_utils.py    # Encapsulation réseau (en trames JSON, délimitées par \n)
├── enzo.py             # Point d'entrée serveur (destinataire)
├── enrik.py            # Point d'entrée client (expéditeur)
└── requirements.txt    # Dépendances (cryptography)
``` 

</br>

## 3. Installation et exécution

### Prérequis :
- Python 3.10+
- Librairie `cryptographie`

</br>

```
pip install -r requirements.txt
```

</br>

### Exécution :

**Ouvrir 2 terminaux distincts :**

1. **TERMINAL N°1 | Enzo (Serveur)**

```
python3 enzo.py
```

</br>

2. **TERMINAL N°2 | Enrik (Client)**

```
python3 enrik.py
```

> [!IMPORTANT]
> Au lancement de chaque script (Serveur ou Client), un input permet de sélectionner le mode **PEDAGOGIQUE** en répondant `Y`, ou refuser avec `n` .

</br>

## 4. 


</br>

## 5.