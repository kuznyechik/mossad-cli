# mossad-cli

Archive chiffrée moderne en Rust — compression, chiffrement Kuznyechik (CTR), plausible deniability.

## Présentation

**mossad-cli** est un outil en ligne de commande pour créer des archives chiffrées au format propriétaire `.mossad`.

| Fonction | Implémentation |
|----------|----------------|
| Compression | DEFLATE |
| Chiffrement | Kuznyechik (mode CTR) |
| Dérivation de clé | Argon2id |
| Authentification | Encrypt-then-MAC (HMAC-SHA256) |
| Intégrité | CRC64 par fichier |

Le projet privilégie la lisibilité du code et la robustesse cryptographique.

## Fonctionnalités

- Format `.mossad` auto-descriptif et versionné
- Streaming (consommation mémoire constante)
- Double volume caché (plausible deniability)
- Barre de progression
- Saisie du mot de passe masquée

## Installation

```bash
git clone https://github.com/kuznyechik/mossad-cli
cd mossad-cli
cargo build --release
```

## Utilisation

**Créer une archive**

```bash
mossad compress dossier/
```

**Extraire une archive**

```bash
mossad extract archive.mossad
```

## Sécurité

Ce projet n'a pas fait l'objet d'un audit externe. L'utilisation en environnement de production est à vos risques.

Pour signaler une vulnérabilité : ouvrir une issue ou me contacter directement.

## Contribuer

Les contributions sont bienvenues, notamment sur :

- Audit de sécurité et fuzzing
- Documentation
- Refactoring

## Licence

MIT
