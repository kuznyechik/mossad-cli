# 🕶️ mossad-cli

> **Archive chiffrée moderne `.mossad` en Rust**  
> Compression + chiffrement **Kuznyechik (CTR)** + plausible deniability  
> Projet sérieux, format propriétaire, zéro bullshit.

---

## 🚀 Présentation

**mossad-cli** est un outil **CLI Rust** permettant de :

- 📦 archiver **des dossiers entiers**
- 🗜️ compresser (DEFLATE)
- 🔐 chiffrer avec **Kuznyechik en mode CTR**
- 🔑 dériver les clés via **Argon2id**
- 🕵️ fournir une **plausible deniability réelle**
- 🧱 utiliser un **format propriétaire robuste : `.mossad`**

Le projet vise un équilibre clair :
> **simplicité d’usage**, **robustesse crypto**, **lisibilité du code**

---

## ✨ Fonctionnalités principales

- ✅ Format `.mossad` auto‑descriptif et versionné
- ✅ Encrypt‑then‑MAC (HMAC‑SHA256)
- ✅ CRC64 par fichier
- ✅ Streaming (RAM constante)
- ✅ Barre de progression
- ✅ Mot de passe masqué
- ✅ Double volume caché (HARD)

---

## 📦 Exemple d’utilisation

### 🔒 Créer une archive

```bash
mossad compress dossier/
```

### 🔓 Extraire

```bash
mossad extract archive.mossad
```

Mot de passe incorrect :
```
Gros nul c'est pas le bon mdp
```

---

## 🤝 Contribuer

Les contributions sont **bienvenues** :
- sécurité
- fuzzing
- refactor
- docs

```bash
git clone https://github.com/tonpseudo/mossad-cli
cargo build
```

---

## 📜 Licence

MIT
