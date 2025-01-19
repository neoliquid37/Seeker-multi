# Guide d'Installation

## Prérequis Système
- Debian 12 (recommandé) ou Ubuntu 22.04+
- Minimum 4GB RAM
- 20GB d'espace système
- Un nom de domaine configuré avec les DNS pointant vers votre serveur

## Préparation du Système

1. Mettre à jour le système :
```bash
apt update && apt upgrade -y
```

2. Installation des dépendances :
```bash
apt install -y \
    curl \
    git \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    sudo \
    quota \
    fail2ban
```

3. Installation de Docker :
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

4. Installation de Docker Compose :
```bash
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

## Installation de la Seedbox

1. Cloner le repository :
```bash
git clone https://github.com/votre-username/seedbox-multi.git /opt/seedbox
cd /opt/seedbox
```

2. Configurer les variables d'environnement :
```bash
cp .env.example .env
nano .env
```

3. Créer la structure des dossiers :
```bash
./scripts/install.sh
```

4. Configuration d'Authelia :
```bash
cd configs/authelia
cp configuration.yml.example configuration.yml
cp users_database.yml.example users_database.yml
# Éditer les fichiers avec vos paramètres
```

5. Configuration de votre domaine :
- Éditer tous les fichiers dans configs/traefik/
- Remplacer "votredomaine.com" par votre domaine

6. Démarrer les services :
```bash
docker-compose up -d
```

## Vérification Post-Installation

1. Vérifier que tous les containers sont en cours d'exécution :
```bash
docker-compose ps
```

2. Tester l'accès :
- https://home.votredomaine.com (Homarr)
- https://auth.votredomaine.com (Authelia)

3. Vérifier les logs :
```bash
docker-compose logs -f
```

## Configuration des Services

### Plex
1. Accéder à https://plex.votredomaine.com
2. Suivre l'assistant de configuration
3. Ajouter les bibliothèques pour chaque utilisateur

### Sonarr/Radarr
1. Configurer les qualités dans Recyclarr
2. Configurer les chemins de téléchargement
3. Connecter à Prowlarr

### Prowlarr
1. Ajouter vos indexeurs
2. Configurer FlareSolverr si nécessaire
3. Connecter à Sonarr/Radarr

## Sécurité

1. Fail2ban est installé et configuré par défaut
2. Les quotas sont activés
3. L'authentification 2FA peut être activée dans Authelia

## Prochaines Étapes

1. Configurer les sauvegardes dans Duplicati
2. Configurer les notifications dans Notifiarr
3. Ajouter vos utilisateurs avec ./scripts/add_user.sh
4. Configurer les quotas avec ./scripts/update_quotas.sh
