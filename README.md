# Seeker-multi
Cette configuration permet de déployer une seedbox multi-utilisateurs complète avec :
- Authentification centralisée
- Espaces utilisateurs séparés
- Quotas de stockage
- Interface moderne
- Monitoring complet

## Prérequis
- Debian 12 (recommandé) ou Ubuntu 22.04+
- Docker et Docker Compose
- Un nom de domaine configuré
- Au moins 4GB de RAM
- 20GB d'espace disque pour le système

## Installation Rapide

```bash
git clone https://github.com/votre-repo/seedbox-multi.git
cd seedbox-multi
cp .env.example .env
# Éditer .env avec vos paramètres
./install.sh
```

## Services Inclus
- 🔐 Authentification : Authelia
- 🖥️ Interface : Homarr
- 📥 Téléchargement : qBittorrent + VueTorrent
- 🎬 Médias : Sonarr, Radarr, Bazarr
- 🎥 Streaming : Plex
- 📊 Monitoring : Uptime Kuma, Scrutiny
- 🔄 Maintenance : Watchtower, Recyclarr
- 💾 Backup : Duplicati
- 📢 Notifications : Notifiarr

## Configuration

Voir [INSTALLATION.md](docs/INSTALLATION.md) pour les instructions détaillées.

## Gestion des Utilisateurs

Utiliser les scripts dans `scripts/` pour gérer les utilisateurs :
```bash
./scripts/add_user.sh username
./scripts/remove_user.sh username
./scripts/update_quotas.sh username 500 # 500GB
```

## Maintenance

Voir [MAINTENANCE.md](docs/MAINTENANCE.md) pour les tâches courantes :
- Backup des configurations
- Mise à jour des services
- Gestion des quotas
- Monitoring

## Contribution

Les pull requests sont les bienvenues. Pour les changements majeurs, ouvrez d'abord une issue.

## Support

En cas de problème, consultez [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).
