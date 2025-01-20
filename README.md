# Seedbox Multi-Utilisateurs

Une solution complète de seedbox multi-utilisateurs avec isolation des espaces et services pour chaque utilisateur.

## 🚀 Caractéristiques

### 📋 Services Par Utilisateur
- 🖥️ Homarr (Dashboard personnel)
- 📥 qBittorrent + VueTorrent (Client torrent)
- 📺 Sonarr (Séries TV)
- 🎬 Radarr (Films)
- 📚 Readarr (Livres)
- 💬 Bazarr (Sous-titres)
- 🔍 Prowlarr (Indexeurs)
- 📝 Overseerr (Requêtes)
- 📖 Calibre-web (Bibliothèque ebooks)
- 📂 Filebrowser (Accès fichiers)

### 🛡️ Services Administrateur
- 🔐 Traefik (Reverse proxy)
- 🎥 Plex (Streaming)
- 📊 Uptime Kuma (Monitoring)
- 💽 Scrutiny (Surveillance disques)
- 🔄 Watchtower (Mises à jour)
- 💾 Duplicati (Backup)
- 🚦 FlareSolverr (By-pass Cloudflare)

### 🔒 Sécurité
- Authentification centralisée (Authelia)
- SSL/TLS automatique (Let's Encrypt)
- Protection fail2ban
- Espaces utilisateurs isolés
- Quotas par utilisateur

## 🔧 Prérequis

### Matériel Recommandé
- CPU : 4 cœurs minimum
- RAM : 8 GB minimum
- Stockage : 20 GB minimum pour le système
- Connexion : 100 Mbps minimum

### Système
- Ubuntu 22.04 LTS
- Un nom de domaine pointant vers votre serveur
- Ports 80/443 ouverts

## 📥 Installation

1. Cloner le repository :
```bash
git clone https://github.com/votre-repo/seedbox.git
cd seedbox
```

2. Rendre le script exécutable :
```bash
chmod +x install.sh
```

3. Lancer l'installation :
```bash
sudo ./install.sh
```

4. Suivre la configuration interactive.

## ⚙️ Configuration

L'installation vous demandera de configurer :
- Domaine et email
- Stockage et quotas
- Paramètres de sécurité
- Configuration des backups
- Utilisateurs initiaux

## 👥 Gestion des Utilisateurs

### Ajouter un utilisateur
```bash
./scripts/add_user.sh username password email
```

### Modifier un quota
```bash
./scripts/update_quota.sh username 500 # 500GB
```

### Supprimer un utilisateur
```bash
./scripts/remove_user.sh username
```

## 📁 Structure des Dossiers

```
/opt/seedbox/
├── data/
│   └── users/
│       ├── user1/
│       │   ├── downloads/
│       │   ├── tv/
│       │   ├── movies/
│       │   └── books/
│       └── user2/
│           └── ...
├── config/
│   ├── traefik/
│   ├── authelia/
│   └── ...
└── scripts/
```

## 🌐 Accès

- Dashboard : `https://home.votredomaine.com`
- Administration : `https://traefik.votredomaine.com`
- Services : `https://{service}.votredomaine.com`

## 🔧 Maintenance

### Backups
- Configuration automatique via Duplicati
- Sauvegarde des configurations
- Sauvegarde des données utilisateurs

### Mises à jour
- Mises à jour automatiques via Watchtower
- Planification configurable
- Logs de mise à jour

### Monitoring
- Surveillance via Uptime Kuma
- Monitoring des disques via Scrutiny
- Alertes configurables

## 📝 Notes

- Chaque utilisateur a son espace isolé
- Les quotas sont appliqués par utilisateur
- La maintenance est automatisée
- Les backups sont configurables
- Le monitoring est centralisé

## ⚠️ Support

Pour toute question ou problème :
- Ouvrez une issue sur GitHub
- Consultez la documentation dans `/docs`
- Vérifiez les logs dans `/logs`

## 🔄 Mises à jour

Le script peut être mis à jour via :
```bash
git pull
./scripts/update.sh
```

## 📜 License

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.
