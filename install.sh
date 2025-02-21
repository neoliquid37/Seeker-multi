#!/bin/bash

#######################
# Fonctions de débogage
#######################
debug_log() {
    local message="$1"
    echo -e "${BLUE}[DEBUG][$(date '+%Y-%m-%d %H:%M:%S')]${NC} $message" >&2
}

inspect_docker_compose() {
    local file="$1"
    local message="$2"
    
    debug_log "=== Inspection du fichier ($message) ==="
    debug_log "Contenu du fichier $file :"
    cat "$file" | while IFS= read -r line; do
        echo "    $line"
    done
    debug_log "=== Fin de l'inspection ==="
}

validate_user_data() {
    local username="$1"
    local user_id="$2"
    local compose_file="$3"

    debug_log "Validation des données pour l'utilisateur $username"

    if [[ -z "$username" ]] || [[ -z "$user_id" ]] || [[ -z "$compose_file" ]]; then
        error "Données utilisateur invalides : username=$username, user_id=$user_id, compose_file=$compose_file"
    fi

    if [[ ! "$user_id" =~ ^[0-9]+$ ]]; then
        error "ID utilisateur invalide : $user_id"
    fi

    if [[ ! -w "$compose_file" ]]; then
        error "Fichier non accessible en écriture : $compose_file"
    fi

    debug_log "Validation des données utilisateur réussie"
}
#######################
# 1. Variables et constantes
#######################

# Variables de configuration par défaut
DOMAIN="votredomaine.com"
EMAIL="votre@email.com"
INSTALL_DIR="/opt/seedbox"
TZ="Europe/Paris"
DEFAULT_QUOTA="500" # En GB

# Variables de stockage
DATA_DISK="/mnt/data"
DOWNLOAD_DISK="/mnt/downloads"
MEDIA_DISK="/mnt/media"
BACKUP_DEST="/mnt/backup"

# Variables de maintenance
MAINTENANCE_TIME="04:00"
MAINTENANCE_DAY="Sunday"
BACKUP_FREQUENCY="Daily"
BACKUP_RETENTION="30"

# Variables de sécurité
MAX_LOGIN_ATTEMPTS=3
BAN_DURATION=30
FORCE_2FA="false"

# Variables Docker
DOCKER_NETWORK="proxy"
DOCKER_SOCKET="/var/run/docker.sock"

# Variables des services
PLEX_CLAIM=""
QB_PORT="6881"
WEBUI_PORT="8080"

# Variables des UID/GID de base
ADMIN_UID="1000"
ADMIN_GID="1000"
START_UID="1001" # UID de départ pour les utilisateurs normaux

set -e  # Stop on error
set -u  # Error on undefined variables
set -o pipefail  # Exit on pipe failures

# Configuration du trap pour le nettoyage
exec 5>&1
trap 'cleanup $?' EXIT

# Tableau pour stocker les utilisateurs
declare -A USERS
declare -a INITIAL_USERS

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions de base pour les logs
log() { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Chemins importants
DOCKER_COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
TRAEFIK_CONFIG_DIR="$INSTALL_DIR/traefik"
AUTHELIA_CONFIG_DIR="$INSTALL_DIR/authelia"

# Configuration des services (ports)
declare -A SERVICE_PORTS=(
    ["traefik"]="443"
    ["plex"]="32400"
    ["qbittorrent"]="6881"
    ["sonarr"]="8989"
    ["radarr"]="7878"
    ["readarr"]="8787"
    ["bazarr"]="6767"
    ["prowlarr"]="9696"
    ["overseerr"]="5055"
)

# Liste des services par utilisateur
USER_SERVICES=(
    "qbittorrent"
    "sonarr"
    "radarr"
    "readarr"
    "bazarr"
    "prowlarr"
    "overseerr"
    "homarr"
	"calibre"
    "filebrowser"
)

# Services administrateur uniquement
ADMIN_SERVICES=(
    "traefik"
    "plex"
    "uptime-kuma"
    "scrutiny"
    "watchtower"
    "duplicati"
    "flaresolverr"
)

# Versions des images Docker (pour contrôle de version)
declare -A DOCKER_IMAGES=(
    ["traefik"]="traefik:v2.10"  # Version spécifique de Traefik
    ["authelia"]="authelia/authelia:latest"
    ["plex"]="plexinc/pms-docker:latest"  # Image officielle Plex
    ["qbittorrent"]="linuxserver/qbittorrent:latest"
    ["sonarr"]="linuxserver/sonarr:latest"
    ["radarr"]="linuxserver/radarr:latest"
    ["readarr"]="lscr.io/linuxserver/readarr:develop"
    ["bazarr"]="linuxserver/bazarr:latest"
    ["prowlarr"]="linuxserver/prowlarr:latest"
    ["overseerr"]="sctx/overseerr:latest"
    ["homarr"]="ghcr.io/ajnart/homarr:latest"
    ["calibre"]="linuxserver/calibre-web:latest"
    ["filebrowser"]="filebrowser/filebrowser:latest"
    ["flaresolverr"]="ghcr.io/flaresolverr/flaresolverr:latest"
    ["scrutiny"]="ghcr.io/analogj/scrutiny:master-omnibus"  # Correction du dépôt Scrutiny
    ["watchtower"]="containrrr/watchtower:latest"
    ["uptime-kuma"]="louislam/uptime-kuma:latest"
)

# Configuration des volumes par défaut
declare -A DEFAULT_VOLUMES=(
    ["downloads"]="/downloads"
    ["movies"]="/movies"
    ["tv"]="/tv"
    ["books"]="/books"
)

# États d'installation
declare -A INSTALL_STATUS=(
    ["system_checked"]=false
    ["dependencies_installed"]=false
    ["docker_installed"]=false
    ["network_configured"]=false
    ["directories_created"]=false
    ["services_configured"]=false
    ["users_configured"]=false
)

#######################
# 2. Fonctions utilitaires
#######################

# Vérification de commande
check_command() {
    local cmd=$1
    if ! command -v "$cmd" &>/dev/null; then
        error "Commande '$cmd' non trouvée. Installation requise."
    fi
}

# Vérification de port
check_port() {
    local port=$1
    if nc -z localhost "$port" 2>/dev/null; then
        error "Le port $port est déjà utilisé"
    fi
}

# Vérification d'espace disque
check_disk_space() {
    local path=$1
    local required=$2
    local available
    available=$(df -BG "$path" | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available" -lt "$required" ]; then
        error "Espace disque insuffisant sur $path. Requis: ${required}G, Disponible: ${available}G"
    fi
}

# Génération de mot de passe aléatoire
generate_password() {
    local length=${1:-32}
    openssl rand -base64 48 | cut -c1-"$length"
}

# Validation d'email
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        error "Format d'email invalide: $email"
    fi
}

# Validation de nom d'utilisateur
validate_username() {
    local username=$1
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        error "Nom d'utilisateur invalide: $username (utilisez uniquement des lettres minuscules, chiffres, - et _)"
    fi
}

# Validation de mot de passe
validate_password() {
    local password=$1
    if [ ${#password} -lt 8 ]; then
        error "Le mot de passe doit contenir au moins 8 caractères"
    fi
}

# Création de dossier sécurisé
create_secure_directory() {
    local dir=$1
    local owner=${2:-root}
    local group=${3:-root}
    local perms=${4:-755}
    
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" || error "Impossible de créer le dossier $dir"
        chmod "$perms" "$dir" || error "Impossible de définir les permissions sur $dir"
        chown "$owner:$group" "$dir" || error "Impossible de changer le propriétaire de $dir"
    fi
}

# Sauvegarde de fichier
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp "$file" "${file}.bak-$(date +%Y%m%d-%H%M%S)" || \
            error "Impossible de sauvegarder $file"
    fi
}

# Vérification de réseau Docker
check_docker_network() {
    local network=$1
    if ! docker network ls | grep -q "$network"; then
        log "Création du réseau Docker $network"
        docker network create "$network" || \
            error "Impossible de créer le réseau Docker $network"
    fi
}

# Affichage de la progression
show_progress() {
    local current=$1
    local total=$2
    local prefix=${3:-"Progress"}
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r%s [%s%s] %d%%" \
        "$prefix" \
        "$(printf '#%.0s' $(seq 1 "$completed"))" \
        "$(printf ' %.0s' $(seq 1 "$remaining"))" \
        "$percentage"
    
    if [ "$current" -eq "$total" ]; then
        echo
    fi
}

# Vérification des prérequis système
check_system_requirements() {
    log "Vérification des prérequis système..."
    
    # Vérification de l'espace disque
    local required_space=20  # Go
    local available_space
    available_space=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "${available_space}" -lt "${required_space}" ]; then
        error "Espace disque insuffisant : ${available_space}G disponible, ${required_space}G requis"
    fi

    # Vérification de la RAM
    local required_ram=4  # Go
    local available_ram
    available_ram=$(free -g | awk '/^Mem:/{print $2}')
    if [ "${available_ram}" -lt "${required_ram}" ]; then
        error "RAM insuffisante : ${available_ram}G disponible, ${required_ram}G requis"
    fi

    # Vérification CPU
    local required_cores=2
    local available_cores
    available_cores=$(nproc)
    if [ "${available_cores}" -lt "${required_cores}" ]; then
        error "Nombre de cœurs CPU insuffisant : ${available_cores} disponible, ${required_cores} requis"
    fi

    # Vérification de Docker
    if ! command -v docker >/dev/null 2>&1; then
        error "Docker n'est pas installé"
    fi

    # Vérification de la version de Docker
    local docker_version
    docker_version=$(docker --version | awk '{print $3}' | tr -d ',')
    if ! printf '%s\n' "20.10.0" "$docker_version" | sort -V -C; then
        error "Version de Docker trop ancienne. Version 20.10.0 ou supérieure requise"
    fi

    # Vérification des permissions Docker
    if ! docker ps >/dev/null 2>&1; then
        error "Permissions Docker insuffisantes"
    fi

    log "Vérification des prérequis système terminée avec succès"
}

# Vérification de Docker Compose
validate_docker_compose() {
    local compose_file="$1"
    log "Validation de la configuration Docker Compose..."

    if ! command -v docker-compose &>/dev/null; then
        error "docker-compose n'est pas installé"
    fi  # Changé } en fi

    if [ ! -f "$compose_file" ]; then
        error "Le fichier $compose_file n'existe pas"
    fi  # Changé } en fi

    # Vérification de la syntaxe
    if ! docker-compose -f "$compose_file" config --quiet; then
        # En cas d'erreur, afficher le détail
        docker-compose -f "$compose_file" config
        error "La configuration Docker Compose est invalide"
    fi  # Changé } en fi

    log "Configuration Docker Compose validée"
}

# Test de connexion internet
check_internet() {
    if ! ping -c 1 google.com &>/dev/null; then
        error "Pas de connexion Internet"
    fi
}

# Validation de nom de domaine
validate_domain() {
    local domain=$1
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
        error "Nom de domaine invalide: $domain"
    fi
}

#######################
# 3. Fonctions de vérification système
#######################

# Vérification complète du système
check_system() {
    log "Démarrage des vérifications système..."
    
    # Installation de bc si non présent
    if ! command -v bc &>/dev/null; then
        apt-get update
        apt-get install -y bc
    fi

    # Vérification de l'utilisateur root
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root"
    fi
    
    # Vérification de la connexion internet
    check_internet
    
    # Vérification des prérequis système
    check_system_requirements 8 4 20
    
    # Vérification des commandes requises
    local required_commands=("curl" "wget" "git" "tar" "bc")
    for cmd in "${required_commands[@]}"; do
        check_command "$cmd"
    done
}

# Vérification des points de montage
check_mount_points() {
    log "Vérification des points de montage..."
    
    # Liste des points de montage requis
    local mount_points=("$DATA_DISK" "$DOWNLOAD_DISK" "$MEDIA_DISK")
    
    for mount in "${mount_points[@]}"; do
        if [ ! -d "$mount" ]; then
            create_secure_directory "$mount"
        fi
        
        # Vérification des permissions
        if ! touch "$mount/.write_test" 2>/dev/null; then
            error "Impossible d'écrire dans $mount"
        else
            rm "$mount/.write_test"
        fi
        
        # Vérification du système de fichiers
        local fs_type
        fs_type=$(df -T "$mount" | awk 'NR==2 {print $2}')
        if [[ ! "$fs_type" =~ ^(ext4|xfs|btrfs)$ ]]; then
            warn "Système de fichiers $fs_type sur $mount peut ne pas être optimal"
        fi
    done
}

# Vérification de la configuration réseau
check_network_config() {
    log "Vérification de la configuration réseau..."
    
    # Vérification DNS
    validate_domain "$DOMAIN"
    if ! host "$DOMAIN" >/dev/null 2>&1; then
        warn "Impossible de résoudre le domaine $DOMAIN"
    fi
    
    # Vérification des sous-domaines
    local subdomains=("auth" "home" "traefik" "plex")
    for sub in "${subdomains[@]}"; do
        if ! host "$sub.$DOMAIN" >/dev/null 2>&1; then
            warn "Sous-domaine $sub.$DOMAIN non configuré"
        fi
    done
    
    # Vérification du pare-feu
    if command -v ufw >/dev/null 2>&1; then
        if ! ufw status | grep -q "active"; then
            warn "UFW n'est pas actif"
        fi
    else
        warn "UFW n'est pas installé"
    fi
    
    # Vérification IPv6
    if [[ $(sysctl -n net.ipv6.conf.all.disable_ipv6) -eq 1 ]]; then
        warn "IPv6 est désactivé sur le système"
    fi
}

# Vérification des dépendances système
check_dependencies() {
    log "Vérification des dépendances système..."
    
    local packages=(
        "curl"
        "git"
        "apt-transport-https"
        "ca-certificates"
        "gnupg"
        "lsb-release"
        "sudo"
        "quota"
        "fail2ban"
        "ufw"
        "htop"
        "ncdu"
        "nano"
        "wget"
        "unzip"
        "netcat"
        "dnsutils"
        "apache2-utils"
        "acl"
        "smartmontools"
        "bc"
    )
    
    local missing_packages=()
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            missing_packages+=("$package")
        fi
    done
    
    if [ ${#missing_packages[@]} -gt 0 ]; then
        log "Installation des paquets manquants : ${missing_packages[*]}"
        apt-get update
        apt-get install -y "${missing_packages[@]}" || \
            error "Impossible d'installer les paquets requis"
    fi
}

# Vérification de l'environnement Docker
check_docker_environment() {
    log "Vérification de l'environnement Docker..."
    
    # Vérification de Docker
    if ! command -v docker >/dev/null 2>&1; then
        error "Docker n'est pas installé"
    fi
    
    # Vérification de Docker Compose
    if ! command -v docker-compose >/dev/null 2>&1; then
        error "Docker Compose n'est pas installé"
    fi
    
    # Vérification du service Docker
    if ! systemctl is-active --quiet docker; then
        error "Le service Docker n'est pas actif"
    fi
    
    # Vérification du réseau Docker
    check_docker_network "$DOCKER_NETWORK"
    
    # Vérification des permissions Docker
    if [ ! -r "$DOCKER_SOCKET" ]; then
        error "Impossible d'accéder au socket Docker"
    fi
}


#######################
# 4. Fonctions d'installation de base
#######################

# Installation des dépendances système
install_dependencies() {
    log "Installation des dépendances..."
    
    # Mise à jour du système
    apt-get update && apt-get upgrade -y

    # Installation des dépendances de base
    apt-get install -y \
        curl \
        git \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        sudo \
        quota \
        fail2ban \
        ufw \
        htop \
        ncdu \
        nano \
        wget \
        unzip \
        netcat \
        dnsutils \
        apache2-utils \
        acl \
        smartmontools \
        bc

    log "Installation des dépendances terminée"
}

# Installation de Docker
install_docker() {
    log "Installation de Docker..."

    # Installation des prérequis
    apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Ajout de la clé GPG officielle de Docker
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

    # Configuration du repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Mise à jour de la liste des paquets
    apt-get update

    # Installation de Docker et des outils
    apt-get install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin

    # Démarrage et activation du service
    systemctl start docker
    systemctl enable docker

    # Installation spécifique de Docker Compose
    log "Installation de Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/download/v2.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Création du lien symbolique
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    # Vérification de l'installation
    if ! docker-compose --version; then
        error "Installation de Docker Compose échouée"
    fi
    
    log "Installation de Docker Compose terminée"
}

# Configuration du pare-feu
setup_firewall() {
    log "Configuration du pare-feu (UFW)..."

    # Installation de UFW si nécessaire
    if ! command -v ufw >/dev/null 2>&1; then
        apt-get install -y ufw || error "Installation de UFW échouée"
    fi

    # Configuration de base
    ufw default deny incoming
    ufw default allow outgoing

    # Ports requis
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow 32400/tcp  # Plex
    ufw allow 6881/tcp   # qBittorrent
    ufw allow 6881/udp   # qBittorrent

    # Activation de UFW
    if ! ufw status | grep -q "active"; then
        echo "y" | ufw enable
    else
        warn "UFW est déjà actif"
    fi

    log "Configuration du pare-feu terminée"
}

# Configuration système de base
setup_system() {
    log "Configuration système de base..."

    # Configuration du fuseau horaire
    timedatectl set-timezone "$TZ" || warn "Impossible de configurer le fuseau horaire"

    # Configuration des quotas
    if ! grep -q "usrquota" /etc/fstab; then
        backup_file "/etc/fstab"
        sed -i 's/ defaults / defaults,usrquota /g' /etc/fstab
        mount -o remount,usrquota /
        quotacheck -cum /
        quotaon -v /
    fi

    # Configuration de fail2ban
    if [ -f "/etc/fail2ban/jail.local" ]; then
        backup_file "/etc/fail2ban/jail.local"
    fi

    cat > "/etc/fail2ban/jail.local" << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = $MAX_LOGIN_ATTEMPTS

[traefik-auth]
enabled = true
port = http,https
filter = traefik-auth
logpath = /var/log/traefik/access.log
maxretry = $MAX_LOGIN_ATTEMPTS
bantime = ${BAN_DURATION}m
EOF

    systemctl restart fail2ban

    log "Configuration système terminée"
}

# Préparation des dossiers
prepare_directories() {
    log "Préparation des dossiers d'installation..."

    # Création des dossiers principaux
    create_secure_directory "$INSTALL_DIR"
    create_secure_directory "$DATA_DISK"
    create_secure_directory "$DOWNLOAD_DISK"
    create_secure_directory "$MEDIA_DISK"
    [ "$ENABLE_BACKUP" = "true" ] && create_secure_directory "$BACKUP_DEST"

    # Dossiers de service
    local service_dirs=(
        "traefik"
        "authelia"
        "plex"
        "uptime-kuma"
        "scrutiny/config"
        "recyclarr/config"
        "recyclarr/cache"
        "duplicati/config"
        "duplicati/backups"
    )

    for dir in "${service_dirs[@]}"; do
        create_secure_directory "$INSTALL_DIR/$dir"
    done

    # Configuration des services
    configure_authelia  # Ajout de l'appel ici

    # Fichiers spéciaux
    touch "$INSTALL_DIR/traefik/acme.json"
    chmod 600 "$INSTALL_DIR/traefik/acme.json"

    log "Préparation des dossiers terminée"
}

# Configuration des quotas
# Configuration finale des quotas
setup_quotas_final() {
    log "Configuration finale des quotas..."
    
    # Désactiver les quotas existants
    quotaoff -avug || true
    
    # Sauvegarder fstab
    backup_file "/etc/fstab"
    
    # Vérifier si les options de quota sont déjà dans fstab
    if ! grep -q "usrquota,grpquota" /etc/fstab; then
        # Ajouter les options de quota pour la partition racine
        sed -i 's|\(defaults\)|\1,usrquota,grpquota|' /etc/fstab
        
        # Remonter le système de fichiers avec les nouveaux paramètres
        mount -o remount,usrquota,grpquota /
    fi
    
    # Créer les fichiers de quota si nécessaire
    if [ ! -f /aquota.user ] || [ ! -f /aquota.group ]; then
        quotacheck -cugm /
    fi
    
    # Activer les quotas
    quotaon -av
    
    # Vérifier que les quotas sont activés
    if ! quotaon -ap 2>/dev/null; then
        warn "Les quotas n'ont pas pu être activés complètement"
    else
        log "Configuration des quotas terminée avec succès"
    fi
}
#######################
# 5. Fonctions de génération de configuration Docker
#######################

# Génération du fichier docker-compose principal
generate_base_docker_compose() {
    log "Génération de la configuration Docker de base..."
    
    local compose_file="$INSTALL_DIR/docker-compose.yml"
    local temp_file=$(mktemp)
    
    # Génération dans un fichier temporaire
    {
        echo "version: '3'"
        echo ""
        echo "services:"
        echo ""
        
        # Services de base
        generate_traefik_config
        echo ""
        generate_authelia_config
        echo ""
        generate_admin_services
        echo ""
        
        # Services utilisateur
        for user_info in "${INITIAL_USERS[@]}"; do
            if [ -n "$user_info" ]; then
                IFS=':' read -r username password _ <<< "$user_info"
                if [ -n "$username" ]; then
                    local user_id=$((1000 + $(get_next_user_id)))
                    generate_user_services "$username" "$user_id"
                    echo ""
                fi
            fi
        done
        
        # Section networks à la fin
        echo "networks:"
        echo "  proxy:"
        echo "    external: true"
    } > "$temp_file"
    
    # Validation du fichier temporaire
    if docker-compose -f "$temp_file" config --quiet; then
        # Si la validation réussit, déplacer le fichier
        mv "$temp_file" "$compose_file"
    else
        # En cas d'erreur, afficher le contenu et nettoyer
        cat "$temp_file"
        rm "$temp_file"
        error "Configuration Docker Compose invalide"
    fi
}

# Fonction de validation du fichier
validate_compose_file() {
    local compose_file="$1"
    
    # Vérifier si le fichier existe
    if [ ! -f "$compose_file" ]; then
        error "Le fichier $compose_file n'existe pas"
    fi

    # Vérifier la structure de base
    if ! grep -q "^version: '3'" "$compose_file"; then
        error "Version manquante dans le fichier docker-compose.yml"
    fi

    if ! grep -q "^services:" "$compose_file"; then
        error "Section services manquante dans le fichier docker-compose.yml"
    fi

    if ! grep -q "^networks:" "$compose_file"; then
        error "Section networks manquante dans le fichier docker-compose.yml"
    fi
}

# Configuration Traefik
# Fonction de base pour la génération
generate_traefik_config() {
    cat << EOT
  traefik:
    image: traefik:latest
    container_name: traefik
    command:
      - "--api.dashboard=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email=${EMAIL}"
      - "--certificatesresolvers.letsencrypt.acme.storage=/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./traefik/acme.json:/acme.json"
      - "./traefik/config:/etc/traefik"
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.traefik.rule=Host(\`traefik.${DOMAIN}\`)"
      - "traefik.http.routers.traefik.service=api@internal"
      - "traefik.http.routers.traefik.middlewares=authelia@docker,admin-only@docker"
    restart: unless-stopped
EOT
}

# Configuration du conteneur Authelia dans docker-compose.yml
generate_authelia_config() {
    cat << EOT
  authelia:
    image: authelia/authelia:latest
    container_name: authelia
    volumes:
      - ./authelia:/config
    environment:
      - TZ=${TZ}
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.authelia.rule=Host(\`auth.${DOMAIN}\`)"
      - "traefik.http.services.authelia.loadbalancer.server.port=9091"
      - "traefik.http.routers.authelia.tls.certresolver=letsencrypt"
    restart: unless-stopped
EOT
}

# Configuration du service Authelia lui-même
configure_authelia() {
    local config_dir="$INSTALL_DIR/authelia"
    local encryption_key=$(openssl rand -hex 64)

    # Création des fichiers de configuration
    mkdir -p "$config_dir"
    
    # Configuration principale
    cat > "$config_dir/configuration.yml" << EOL
---
server:
  host: 0.0.0.0
  port: 9091

log:
  level: info

authentication_backend:
  file:
    path: /config/users_database.yml

access_control:
  default_policy: one_factor
  rules:
    - domain: "*.${DOMAIN}"
      policy: one_factor

session:
  name: authelia_session
  domain: ${DOMAIN}
  expiration: 3600
  inactivity: 300
  secret: ${encryption_key}

storage:
  local:
    path: /config/db.sqlite3
  encryption_key: ${encryption_key}

notifier:
  filesystem:
    filename: /config/notification.txt

access_control:
  default_policy: deny
  rules:
    - domain: "auth.${DOMAIN}"
      policy: bypass
    - domain: "*.${DOMAIN}"
      policy: one_factor
EOL

    # Correction des permissions
    chown -R "$ADMIN_UID:$ADMIN_GID" "$config_dir"
    chmod 600 "$config_dir/configuration.yml"
}

generate_admin_services() {
    cat << EOT
  plex:
    image: linuxserver/plex:latest
    container_name: plex
    network_mode: host
    environment:
      - PUID=${ADMIN_UID}
      - PGID=${ADMIN_GID}
      - TZ=${TZ}
      - PLEX_CLAIM=${PLEX_CLAIM}
    volumes:
      - ./plex:/config
      - ${MEDIA_DISK}:/data
    restart: unless-stopped

  flaresolverr:
    image: ghcr.io/flaresolverr/flaresolverr:latest
    container_name: flaresolverr
    environment:
      - LOG_LEVEL=info
      - LOG_HTML=false
      - CAPTCHA_SOLVER=none
      - TZ=${TZ}
    networks:
      - proxy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8191/v1"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
EOT

    generate_monitoring_services
}

generate_monitoring_services() {
    cat << EOT
  uptime-kuma:
    image: louislam/uptime-kuma:latest
    container_name: uptime-kuma
    volumes:
      - ./uptime-kuma:/app/data
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.uptime.rule=Host(\`uptime.${DOMAIN}\`)"
      - "traefik.http.routers.uptime.middlewares=authelia@docker,admin-only@docker"
    restart: unless-stopped

  scrutiny:
    image: ghcr.io/analogj/scrutiny:master-omnibus
    container_name: scrutiny
    privileged: true
    ports:
      - "8080:8080"
      - "8086:8086"
    volumes:
      - ./scrutiny/config:/opt/scrutiny/config
      - ./scrutiny/influxdb:/opt/scrutiny/influxdb
      - /run/udev:/run/udev:ro
    cap_add:
      - SYS_RAWIO
      - SYS_ADMIN  # Pour le support NVMe
    devices:
      - /dev/sd*:/dev/sd*
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.scrutiny.rule=Host(\`disks.${DOMAIN}\`)"
      - "traefik.http.routers.scrutiny.middlewares=authelia@docker,admin-only@docker"
      - "traefik.http.services.scrutiny.loadbalancer.server.port=8080"
    restart: unless-stopped

  watchtower:
    image: containrrr/watchtower
    container_name: watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_SCHEDULE=0 0 ${MAINTENANCE_TIME#*:} * * *
      - WATCHTOWER_CLEANUP=true
    restart: unless-stopped
EOT
}

generate_backup_services() {
    cat << EOT
  duplicati:
    image: linuxserver/duplicati:latest
    container_name: duplicati
    environment:
      - PUID=${ADMIN_UID}
      - PGID=${ADMIN_GID}
      - TZ=${TZ}
    volumes:
      - ./duplicati/config:/config
      - ./duplicati/backups:/backups
      - ${DATA_DISK}:/source
      - ${BACKUP_DEST}:/backup-destination
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.duplicati.rule=Host(\`backup.${DOMAIN}\`)"
      - "traefik.http.routers.duplicati.middlewares=authelia@docker,admin-only@docker"
      - "traefik.http.services.duplicati.loadbalancer.server.port=8200"
    restart: unless-stopped
EOT
}

# Génération services utilisateur
generate_user_services() {
    local username=$1
    local user_id=$2
    
    # Génération directe avec heredoc
    cat << EOT
  homarr-${username}:
    image: ${DOCKER_IMAGES[homarr]:-ghcr.io/ajnart/homarr:latest}
    container_name: homarr-${username}
    environment:
      - PUID=${user_id}
      - PGID=${user_id}
      - TZ=${TZ}
    volumes:
      - ./homarr/${username}:/app/data/configs
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.homarr-${username}.rule=Host(\`home.${DOMAIN}\`) && Headers(\`Remote-User\`, \`${username}\`)"
      - "traefik.http.routers.homarr-${username}.middlewares=authelia@docker"
    restart: unless-stopped

  calibre-${username}:
    image: ${DOCKER_IMAGES[calibre]:-linuxserver/calibre-web:latest}
    container_name: calibre-${username}
    environment:
      - PUID=${user_id}
      - PGID=${user_id}
      - TZ=${TZ}
    volumes:
      - ./calibre/${username}:/config
      - ./data/users/${username}/books:/books
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.calibre-${username}.rule=Host(\`books.${DOMAIN}\`) && Headers(\`Remote-User\`, \`${username}\`)"
      - "traefik.http.routers.calibre-${username}.middlewares=authelia@docker"
      - "traefik.http.services.calibre-${username}.loadbalancer.server.port=8083"
    restart: unless-stopped

  files-${username}:
    image: ${DOCKER_IMAGES[filebrowser]:-filebrowser/filebrowser:latest}
    container_name: files-${username}
    user: "${user_id}:${user_id}"
    volumes:
      - ./filebrowser/${username}:/config
      - ./data/users/${username}:/data
    environment:
      - TZ=${TZ}
    networks:
      - proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.files-${username}.rule=Host(\`files.${DOMAIN}\`) && Headers(\`Remote-User\`, \`${username}\`)"
      - "traefik.http.routers.files-${username}.middlewares=authelia@docker"
      - "traefik.http.services.files-${username}.loadbalancer.server.port=80"
    restart: unless-stopped
EOT
}

# Finalisation du docker-compose
finalize_docker_compose() {
    local compose_file="$1"
    log "Finalisation du docker-compose.yml..."
    
    cat >> "$compose_file" << EOT

networks:
  proxy:
    external: true
EOT

    # Vérification finale du fichier
    if ! docker-compose -f "$compose_file" config --quiet; then
        error "Validation finale du fichier docker-compose.yml échouée"
    fi
}

#######################
# 6. Fonctions de gestion des utilisateurs
#######################
get_next_user_id() {
    local last_id=1000  # On commence à 1000 comme base
    
    # Trouver le plus grand UID >= 1000
    while IFS=: read -r _ _ uid _; do
        if [[ "$uid" =~ ^[0-9]+$ ]] && [ "$uid" -ge 1000 ] && [ "$uid" -gt "$last_id" ]; then
            last_id=$uid
        fi
    done < /etc/passwd
    
    # Retourner le prochain ID
    echo $((last_id - 1000 + 1))
}

# Création d'un utilisateur complet
create_user() {
    local username=$1
    local password=$2
    local email=$3
    local is_admin=${4:-false}
    local user_id=$((1000 + $(get_next_user_id)))

    log "Création de l'utilisateur: $username"

    # Validation des entrées
    validate_username "$username"
    validate_password "$password"
    validate_email "$email"

    # Création de l'utilisateur système
    create_system_user "$username" "$user_id"

    # Création des dossiers utilisateur
    create_user_directories "$username" "$user_id"

    # Configuration des services
    configure_user_services "$username" "$user_id"

    # Configuration Authelia
    add_authelia_user "$username" "$password" "$email" "$is_admin"

    # Configuration des quotas
    setup_user_quota "$username"

    # Génération des configurations Docker
    generate_user_services "$username" "$user_id" "$INSTALL_DIR/docker-compose.yml"
}

# Création de l'utilisateur système
create_system_user() {
    local username=$1
    local user_id=$2

    log "Création de l'utilisateur système $username"

    if id "$username" &>/dev/null; then
        warn "L'utilisateur système $username existe déjà"
        return
    fi

    useradd -m -u "$user_id" -s /bin/bash "$username" || \
        error "Impossible de créer l'utilisateur système $username"
    
    # Ajout aux groupes nécessaires
    usermod -aG docker "$username"
}
# Création des dossiers utilisateur
create_user_directories() {
    local username=$1
    local user_id=$2

    log "Création des dossiers pour $username"

    # Structure de base utilisateur
    local base_dir="$INSTALL_DIR/data/users/$username"
    
    # Dossiers médias principaux
    declare -a media_dirs=(
        "downloads"
        "downloads/temp"
        "downloads/complete"
        "tv"
        "movies"
        "books"
        "books/library"
        "books/uploads"
        "music"
    )

    # Création des dossiers médias
    for dir in "${media_dirs[@]}"; do
        create_secure_directory "$base_dir/$dir" "$username" "$username" "755"
    done

    # Dossiers de configuration des services
    declare -a service_dirs=(
        "qbittorrent"
        "sonarr"
        "radarr"
        "readarr"
        "bazarr"
        "prowlarr"
        "overseerr"
        "homarr"
        "calibre"
        "filebrowser"
    )

    # Création des dossiers de configuration
    for service in "${service_dirs[@]}"; do
        create_secure_directory "$INSTALL_DIR/$service/$username" "$username" "$username" "755"
    done

    # Configuration spécifique pour Calibre
    local calibre_config_dir="$INSTALL_DIR/calibre/$username"
    mkdir -p "$calibre_config_dir/config"
    mkdir -p "$calibre_config_dir/database"
    chown -R "$user_id:$user_id" "$calibre_config_dir"

    # Configuration spécifique pour Filebrowser
    local filebrowser_config_dir="$INSTALL_DIR/filebrowser/$username"
    mkdir -p "$filebrowser_config_dir/config"
    mkdir -p "$filebrowser_config_dir/database"
    touch "$filebrowser_config_dir/database/filebrowser.db"
    chown -R "$user_id:$user_id" "$filebrowser_config_dir"

    log "Structure de dossiers créée pour $username"

    # Vérification des permissions
    find "$base_dir" -type d -exec chmod 755 {} \;
    find "$base_dir" -type f -exec chmod 644 {} \;
    chown -R "$user_id:$user_id" "$base_dir"
}

# Configuration des services pour un utilisateur
configure_user_services() {
    local username=$1
    local user_id=$2

    log "Configuration des services pour $username"

    # Configuration qBittorrent
    configure_qbittorrent "$username" "$user_id"

    # Configuration Sonarr
    configure_sonarr "$username" "$user_id"

    # Configuration Radarr
    configure_radarr "$username" "$user_id"

    # Configuration Readarr
    configure_readarr "$username" "$user_id"

    # Configuration Bazarr
    configure_bazarr "$username" "$user_id"

    # Configuration Overseerr
    configure_overseerr "$username" "$user_id"
}

# Ajout d'un utilisateur dans Authelia
add_authelia_user() {
    local username=$1
    local password=$2
    local email=$3
    local is_admin=${4:-false}

    log "Configuration Authelia pour $username"

    # Génération du hash du mot de passe
    local password_hash
    password_hash=$(docker run --rm authelia/authelia:latest authelia hash-password "$password")

    # Ajout de l'utilisateur dans la configuration
    cat >> "$INSTALL_DIR/authelia/users_database.yml" << EOF
  $username:
    displayname: "$username"
    password: "$password_hash"
    email: "$email"
    groups:
      - users
EOF

    # Ajout du groupe admin si nécessaire
    if [ "$is_admin" = "true" ]; then
        sed -i "/groups:/a\      - admins" "$INSTALL_DIR/authelia/users_database.yml"
    fi
}

# Configuration des quotas utilisateur
setup_user_quota() {
    local username=$1
    local quota_size=${2:-$DEFAULT_QUOTA}

    log "Configuration du quota pour $username"

    # Conversion en KB (quota utilise des blocs de 1KB)
    local quota_kb=$((quota_size * 1024 * 1024))

    # Application du quota
    setquota -u "$username" 0 "$quota_kb" 0 0 / || \
        error "Impossible de configurer le quota pour $username"
}

# Suppression d'un utilisateur
delete_user() {
    local username=$1
    local keep_data=${2:-false}

    log "Suppression de l'utilisateur $username"

    # Arrêt des services de l'utilisateur
    stop_user_services "$username"

    # Suppression des configurations Docker
    remove_user_services "$username"

    # Suppression des données si demandé
    if [ "$keep_data" = "false" ]; then
        rm -rf "$INSTALL_DIR/data/users/$username"
    fi

    # Suppression des configurations de service
    for service in "${USER_SERVICES[@]}"; do
        rm -rf "$INSTALL_DIR/$service/$username"
    done

    # Suppression de l'utilisateur système
    userdel -r "$username" 2>/dev/null || true

    # Suppression de l'utilisateur d'Authelia
    sed -i "/^  $username:/,/^$/d" "$INSTALL_DIR/authelia/users_database.yml"

    log "Utilisateur $username supprimé avec succès"
}

# Modification du quota utilisateur
modify_user_quota() {
    local username=$1
    local new_quota=$2

    log "Modification du quota pour $username"

    # Vérification de l'existence de l'utilisateur
    if ! id "$username" &>/dev/null; then
        error "L'utilisateur $username n'existe pas"
    fi

    # Application du nouveau quota
    setup_user_quota "$username" "$new_quota"

    log "Quota modifié pour $username: ${new_quota}GB"
}


#######################
# 7. Fonctions de configuration des services
#######################

# Configuration de qBittorrent
configure_qbittorrent() {
    local username=$1
    local user_id=$2
    
    log "Configuration de qBittorrent pour $username"
    
    local config_dir="$INSTALL_DIR/qbittorrent/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/qBittorrent.conf" << EOF
[Preferences]
WebUI\Username=$username
WebUI\Password=$(echo -n "defaultpass" | md5sum | cut -d ' ' -f 1)
Downloads\SavePath=/downloads/
Downloads\TempPath=/downloads/temp/
WebUI\Port=8080
Connection\PortRangeMin=6881
Connection\PortRangeMax=6881
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration de Sonarr
configure_sonarr() {
    local username=$1
    local user_id=$2
    
    log "Configuration de Sonarr pour $username"
    
    local config_dir="$INSTALL_DIR/sonarr/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/config.xml" << EOF
<Config>
  <LogLevel>info</LogLevel>
  <ApiKey>$(openssl rand -hex 32)</ApiKey>
  <AuthenticationMethod>External</AuthenticationMethod>
  <BindAddress>*</BindAddress>
  <Port>8989</Port>
  <UrlBase>/$username</UrlBase>
  <DownloadClient>
    <Implementation>QBittorrent</Implementation>
    <Host>qbittorrent-$username</Host>
    <Port>8080</Port>
    <Username>$username</Username>
  </DownloadClient>
</Config>
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration de Radarr
configure_radarr() {
    local username=$1
    local user_id=$2
    
    log "Configuration de Radarr pour $username"
    
    local config_dir="$INSTALL_DIR/radarr/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/config.xml" << EOF
<Config>
  <LogLevel>info</LogLevel>
  <ApiKey>$(openssl rand -hex 32)</ApiKey>
  <AuthenticationMethod>External</AuthenticationMethod>
  <BindAddress>*</BindAddress>
  <Port>7878</Port>
  <UrlBase>/$username</UrlBase>
  <DownloadClient>
    <Implementation>QBittorrent</Implementation>
    <Host>qbittorrent-$username</Host>
    <Port>8080</Port>
    <Username>$username</Username>
  </DownloadClient>
</Config>
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration de Readarr
configure_readarr() {
    local username=$1
    local user_id=$2
    
    log "Configuration de Readarr pour $username"
    
    local config_dir="$INSTALL_DIR/readarr/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/config.xml" << EOF
<Config>
  <LogLevel>info</LogLevel>
  <ApiKey>$(openssl rand -hex 32)</ApiKey>
  <AuthenticationMethod>External</AuthenticationMethod>
  <BindAddress>*</BindAddress>
  <Port>8787</Port>
  <UrlBase>/$username</UrlBase>
  <DownloadClient>
    <Implementation>QBittorrent</Implementation>
    <Host>qbittorrent-$username</Host>
    <Port>8080</Port>
    <Username>$username</Username>
  </DownloadClient>
</Config>
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration de Bazarr
configure_bazarr() {
    local username=$1
    local user_id=$2
    
    log "Configuration de Bazarr pour $username"
    
    local config_dir="$INSTALL_DIR/bazarr/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/config.ini" << EOF
[general]
ip = 0.0.0.0
port = 6767
base_url = /$username
auth_enabled = False

[sonarr]
apikey = 
full_update = Daily
only_monitored = True
base_url = http://sonarr-$username:8989/$username

[radarr]
apikey = 
full_update = Daily
only_monitored = True
base_url = http://radarr-$username:7878/$username
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration d'Overseerr
configure_overseerr() {
    local username=$1
    local user_id=$2
    
    log "Configuration d'Overseerr pour $username"
    
    local config_dir="$INSTALL_DIR/overseerr/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/settings.json" << EOF
{
  "apiKey": "$(openssl rand -hex 32)",
  "port": 5055,
  "baseUrl": "/$username",
  "trustProxy": true,
  "defaultPermissions": 2,
  "defaultQuotas": {
    "movie": {
      "quotaLimit": 5,
      "quotaDays": 7
    },
    "tv": {
      "quotaLimit": 5,
      "quotaDays": 7
    }
  }
}
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration de Prowlarr
configure_prowlarr() {
    local username=$1
    local user_id=$2
    
    log "Configuration de Prowlarr pour $username"
    
    local config_dir="$INSTALL_DIR/prowlarr/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/config.xml" << EOF
<Config>
  <LogLevel>info</LogLevel>
  <ApiKey>$(openssl rand -hex 32)</ApiKey>
  <AuthenticationMethod>External</AuthenticationMethod>
  <BindAddress>*</BindAddress>
  <Port>9696</Port>
  <UrlBase>/$username</UrlBase>
  <FlareSolverr>
    <Host>http://flaresolverr:8191</Host>
    <ApiKey></ApiKey>
    <Tags></Tags>
  </FlareSolverr>
</Config>
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration de Homarr
configure_homarr() {
    local username=$1
    local user_id=$2
    
    log "Configuration de Homarr pour $username"
    
    local config_dir="$INSTALL_DIR/homarr/$username"
    mkdir -p "$config_dir"
    
    cat > "$config_dir/configs/default.json" << EOF
{
  "name": "Dashboard $username",
  "services": [
    {
      "name": "Sonarr",
      "url": "/sonarr/$username",
      "icon": "sonarr.png"
    },
    {
      "name": "Radarr",
      "url": "/radarr/$username",
      "icon": "radarr.png"
    },
    {
      "name": "qBittorrent",
      "url": "/qbittorrent/$username",
      "icon": "qbittorrent.png"
    }
  ]
}
EOF

    chown -R "$user_id:$user_id" "$config_dir"
}

# Configuration de Calibre-web
configure_calibre() {
    local username=$1
    local user_id=$2
    
    log "Configuration de Calibre-web pour $username"
    
    local config_dir="$INSTALL_DIR/calibre/$username"
    local library_dir="$INSTALL_DIR/data/users/$username/books/library"
    
    mkdir -p "$config_dir" "$library_dir"
    
    cat > "$config_dir/config.yml" << EOF
SERVER_PORT: 8083
CALIBRE_DATABASE_PATH: /books/library
UPLOADS_DIR: /books/uploads
LOGIN_REQUIRED: false  # Géré par Authelia
EOF

    # Création de la bibliothèque Calibre par défaut
    calibredb --with-library="$library_dir" create_empty_db

    chown -R "$user_id:$user_id" "$config_dir" "$library_dir"
}

# Correction de la configuration filebrowser
configure_filebrowser() {
    local username=$1
    local user_id=$2
    
    local config_dir="$INSTALL_DIR/filebrowser/$username"
    local database_dir="$config_dir/database"
    
    mkdir -p "$database_dir"
    
    # Configuration correcte du chemin de la base de données
    cat > "$config_dir/settings.json" << EOF
{
  "port": 80,
  "baseURL": "/$username",
  "address": "0.0.0.0",
  "log": "stdout",
  "database": "/database/filebrowser.db",
  "root": "/data",
  "auth.method": "noauth"
}
EOF

    # Correction des permissions
    chown -R "$user_id:$user_id" "$config_dir"
    chmod 755 "$config_dir"
    chmod 755 "$database_dir"
    touch "$database_dir/filebrowser.db"
    chown "$user_id:$user_id" "$database_dir/filebrowser.db"
    chmod 644 "$database_dir/filebrowser.db"
}

#######################
# 8. Configuration interactive
#######################

# Configuration principale
configure_installation() {
    log "Démarrage de la configuration interactive..."
    
    # Configuration du domaine
    configure_domain_settings
    
    # Configuration admin
    configure_admin_settings
    
    # Configuration du stockage
    configure_storage_settings
    
    # Configuration de la sécurité
    configure_security_settings
    
    # Configuration des backups
    configure_backup_settings
    
    # Configuration de la maintenance
    configure_maintenance_settings
    
    # Configuration des utilisateurs
    configure_user_settings
    
    # Affichage du récapitulatif
    show_config_summary
}

# Configuration du domaine
configure_domain_settings() {
    echo -e "\n${BLUE}=== Configuration du domaine ===${NC}"
    
    while true; do
        read -p "Entrez votre nom de domaine (ex: exemple.com): " USER_DOMAIN
        if validate_domain "$USER_DOMAIN"; then
            DOMAIN=$USER_DOMAIN
            break
        else
            warn "Domaine invalide, réessayez"
        fi
    done
    
    while true; do
        read -p "Entrez votre email (pour Let's Encrypt): " USER_EMAIL
        if validate_email "$USER_EMAIL"; then
            EMAIL=$USER_EMAIL
            break
        else
            warn "Email invalide, réessayez"
        fi
    done
}

# Configuration admin
configure_admin_settings() {
    echo -e "\n${BLUE}=== Configuration administrateur ===${NC}"
    
    # Nom d'utilisateur admin
    while true; do
        read -p "Nom d'utilisateur administrateur [admin]: " USER_ADMIN
        ADMIN_USER=${USER_ADMIN:-"admin"}
        if validate_username "$ADMIN_USER"; then
            break
        fi
    done
    
    # Mot de passe admin
    while true; do
        read -s -p "Mot de passe administrateur (min 8 caractères): " ADMIN_PASSWORD
        echo
        if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
            warn "Le mot de passe doit contenir au moins 8 caractères"
            continue
        fi
        read -s -p "Confirmez le mot de passe: " ADMIN_PASSWORD_CONFIRM
        echo
        if [ "$ADMIN_PASSWORD" = "$ADMIN_PASSWORD_CONFIRM" ]; then
            break
        else
            warn "Les mots de passe ne correspondent pas"
        fi
    done
}

# Configuration du stockage
configure_storage_settings() {
    echo -e "\n${BLUE}=== Configuration du stockage ===${NC}"
    
    read -p "Chemin du disque pour les données [$DATA_DISK]: " USER_DATA_DISK
    DATA_DISK=${USER_DATA_DISK:-$DATA_DISK}
    
    read -p "Séparer les disques downloads/média ? (o/N): " SPLIT_DISKS
    if [[ $SPLIT_DISKS =~ ^[oO]$ ]]; then
        read -p "Chemin pour les downloads [$DOWNLOAD_DISK]: " USER_DOWNLOAD_DISK
        DOWNLOAD_DISK=${USER_DOWNLOAD_DISK:-$DOWNLOAD_DISK}
        read -p "Chemin pour les médias [$MEDIA_DISK]: " USER_MEDIA_DISK
        MEDIA_DISK=${USER_MEDIA_DISK:-$MEDIA_DISK}
    fi
}

# Configuration de la sécurité
configure_security_settings() {
    echo -e "\n${BLUE}=== Configuration de la sécurité ===${NC}"
    
    read -p "Activer 2FA pour tous les utilisateurs ? (o/N): " FORCE_2FA
    FORCE_2FA=${FORCE_2FA:-"N"}
    
    read -p "Nombre max de tentatives de connexion [$MAX_LOGIN_ATTEMPTS]: " USER_MAX_ATTEMPTS
    MAX_LOGIN_ATTEMPTS=${USER_MAX_ATTEMPTS:-$MAX_LOGIN_ATTEMPTS}
    
    read -p "Durée de bannissement en minutes [$BAN_DURATION]: " USER_BAN_DURATION
    BAN_DURATION=${USER_BAN_DURATION:-$BAN_DURATION}
}

# Configuration des backups
configure_backup_settings() {
    echo -e "\n${BLUE}=== Configuration des sauvegardes ===${NC}"
    
    read -p "Activer les backups automatiques ? (o/N): " ENABLE_BACKUP
    if [[ $ENABLE_BACKUP =~ ^[oO]$ ]]; then
        read -p "Destination des backups [$BACKUP_DEST]: " USER_BACKUP_DEST
        BACKUP_DEST=${USER_BACKUP_DEST:-$BACKUP_DEST}
        
        while true; do
            read -p "Fréquence des backups (Daily/Weekly/Monthly) [$BACKUP_FREQUENCY]: " USER_BACKUP_FREQ
            USER_BACKUP_FREQ=${USER_BACKUP_FREQ:-$BACKUP_FREQUENCY}
            if [[ "$USER_BACKUP_FREQ" =~ ^(Daily|Weekly|Monthly)$ ]]; then
                BACKUP_FREQUENCY=$USER_BACKUP_FREQ
                break
            else
                warn "Fréquence invalide, utilisez Daily, Weekly ou Monthly"
            fi
        done
        
        read -p "Rétention des backups en jours [30]: " USER_BACKUP_RETENTION
        if [[ "$USER_BACKUP_RETENTION" =~ ^[0-9]+$ ]]; then
            BACKUP_RETENTION=${USER_BACKUP_RETENTION:-30}
        else
            warn "Valeur de rétention invalide, utilisation de la valeur par défaut (30)"
            BACKUP_RETENTION=30
        fi
    fi
}

# Configuration de la maintenance
configure_maintenance_settings() {
    echo -e "\n${BLUE}=== Configuration de la maintenance ===${NC}"
    
    while true; do
        read -p "Heure de maintenance (format 24h) [$MAINTENANCE_TIME]: " USER_MAINT_TIME
        if [[ "$USER_MAINT_TIME" =~ ^([0-1][0-9]|2[0-3]):[0-5][0-9]$ ]] || [ -z "$USER_MAINT_TIME" ]; then
            MAINTENANCE_TIME=${USER_MAINT_TIME:-$MAINTENANCE_TIME}
            break
        else
            warn "Format d'heure invalide (utilisez HH:MM)"
        fi
    done
    
    local valid_days="Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday"
    while true; do
        read -p "Jour de maintenance complète [$MAINTENANCE_DAY]: " USER_MAINT_DAY
        if [[ "$USER_MAINT_DAY" =~ ^($valid_days)$ ]] || [ -z "$USER_MAINT_DAY" ]; then
            MAINTENANCE_DAY=${USER_MAINT_DAY:-$MAINTENANCE_DAY}
            break
        else
            warn "Jour invalide, utilisez un jour de la semaine en anglais"
        fi
    done
}

# Configuration des utilisateurs
configure_user_settings() {
    echo -e "\n${BLUE}=== Configuration des utilisateurs ===${NC}"
    
    INITIAL_USERS=()
    while true; do
        read -p "Ajouter un utilisateur ? (O/n): " ADD_USER
        if [[ $ADD_USER =~ ^[nN]$ ]]; then
            break
        fi
        
        configure_single_user
    done
}

# Configuration d'un utilisateur
configure_single_user() {
    while true; do
        read -p "Nom d'utilisateur: " username
        if validate_username "$username"; then
            break
        fi
    done
    
    while true; do
        read -s -p "Mot de passe: " password
        echo
        if [ ${#password} -lt 8 ]; then
            warn "Le mot de passe doit contenir au moins 8 caractères"
            continue
        fi
        read -s -p "Confirmez le mot de passe: " password_confirm
        echo
        if [ "$password" = "$password_confirm" ]; then
            break
        else
            warn "Les mots de passe ne correspondent pas"
        fi
    done
    
    read -p "Email: " email
    validate_email "$email"
    
    INITIAL_USERS+=("$username:$password:$email")
}

# Affichage du récapitulatif
show_config_summary() {
    echo -e "\n${BLUE}=== Récapitulatif de la configuration ===${NC}"
    echo "Domaine : $DOMAIN"
    echo "Email Admin : $EMAIL"
    echo "Admin : $ADMIN_USER"
    echo "Stockage principal : $DATA_DISK"
    if [[ $SPLIT_DISKS =~ ^[oO]$ ]]; then
        echo "Downloads : $DOWNLOAD_DISK"
        echo "Médias : $MEDIA_DISK"
    fi
    echo "2FA forcé : $FORCE_2FA"
    echo "Backups activés : ${ENABLE_BACKUP}"
    if [[ $ENABLE_BACKUP =~ ^[oO]$ ]]; then
        echo "Destination backups : $BACKUP_DEST"
        echo "Fréquence backups : $BACKUP_FREQUENCY"
    fi
    echo "Maintenance : $MAINTENANCE_TIME ($MAINTENANCE_DAY)"
    echo "Nombre d'utilisateurs : ${#INITIAL_USERS[@]}"
    
    echo -e "\n${YELLOW}Confirmez-vous cette configuration ? (o/N)${NC}"
    read -p "> " confirm
    if [[ ! $confirm =~ ^[oO]$ ]]; then
        error "Installation annulée par l'utilisateur"
    fi
}

#######################
# 9. Fonction principale
#######################

# Fonction de nettoyage
cleanup() {
    local exit_code=${1:-1}  # Valeur par défaut de 1 si non spécifié
    local keep_data=${2:-false}
    
    if [ $exit_code -ne 0 ]; then
        log "Nettoyage après erreur (code: $exit_code)..."
        
        # Arrêt des conteneurs
        if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
            cd "$INSTALL_DIR" && docker-compose down --remove-orphans || true
        fi
        
        # Sauvegarde de la configuration existante
        if [ -d "$INSTALL_DIR" ]; then
            local backup_dir="${INSTALL_DIR}_failed_$(date +%Y%m%d_%H%M%S)"
            mv "$INSTALL_DIR" "$backup_dir"
            log "Configuration sauvegardée dans $backup_dir"
        fi
    fi
}

# Déploiement des services
deploy_services() {
    log "Déploiement des services..."
    
    cd "$INSTALL_DIR" || error "Impossible d'accéder à $INSTALL_DIR"
    
    # Validation de la configuration
    validate_docker_compose "$INSTALL_DIR/docker-compose.yml"
    
    # Création du réseau si nécessaire
    if ! docker network ls | grep -q "proxy"; then
        docker network create proxy
    fi
    
    # Test de disponibilité des images
    log "Vérification des images Docker..."
    local failed_images=()
    for image in "${DOCKER_IMAGES[@]}"; do
        if ! docker pull "$image" &>/dev/null; then
            failed_images+=("$image")
        fi
    done

    if [ ${#failed_images[@]} -gt 0 ]; then
        error "Images inaccessibles: ${failed_images[*]}"
    fi
    
    # Téléchargement des images
    log "Téléchargement des images Docker..."
    if ! docker-compose pull; then
        error "Erreur lors du téléchargement des images"
    fi
    
    # Démarrage des services
    log "Démarrage des services..."
    if ! docker-compose up -d; then
        error "Échec du démarrage des services"
    fi
    
    # Vérification des services
    verify_services
}

# Vérification des services
verify_services() {
    log "Vérification des services..."
    local timeout=600  # 10 minutes
    local interval=10  # 10 secondes
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        local failed_services=()
        local pending_services=()
        
        # Vérifier chaque service individuellement
        while IFS= read -r line; do
            if [[ $line =~ ^([a-zA-Z0-9_-]+)[[:space:]].*[[:space:]]([A-Za-z]+)[[:space:]]*$ ]]; then
                local service="${BASH_REMATCH[1]}"
                local status="${BASH_REMATCH[2]}"
                
                if [ "$status" = "Exit" ]; then
                    failed_services+=("$service")
                    # Afficher les logs du service en échec
                    log "Logs du service $service en échec:"
                    docker-compose logs --tail=50 "$service"
                elif [ "$status" != "Up" ]; then
                    pending_services+=("$service")
                fi
            fi
        done < <(docker-compose ps)
        
        # Si des services ont échoué, tenter de les redémarrer
        if [ ${#failed_services[@]} -gt 0 ]; then
            warn "Services en échec: ${failed_services[*]}"
            for service in "${failed_services[@]}"; do
                log "Tentative de redémarrage de $service..."
                docker-compose restart "$service"
            done
        fi
        
        # Compter les services en cours d'exécution
        local running_count=$(docker-compose ps | grep -c "Up")
        local total_services=$(docker-compose ps | tail -n +2 | wc -l)
        
        if [ "$running_count" -eq "$total_services" ]; then
            log "Tous les services sont démarrés"
            return 0
        fi
        
        if [ ${#pending_services[@]} -gt 0 ]; then
            log "Services en attente: ${pending_services[*]}"
        fi
        
        sleep $interval
        elapsed=$((elapsed + interval))
        show_progress $elapsed $timeout "Démarrage des services"
    done
    
    # Si on arrive ici, c'est un timeout - générer un rapport détaillé
    log "Génération du rapport de statut des services..."
    docker-compose ps
    docker-compose logs --tail=100
    
    error "Timeout lors du démarrage des services après ${timeout}s. Vérifiez les logs ci-dessus pour plus de détails."
}

# Fonction principale
main() {
    # Gestion des erreurs
    set -e
    trap cleanup EXIT
    
    log "Démarrage de l'installation de la seedbox..."
    
    # Vérification des droits root
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root"
    fi
    
    # Configuration interactive
    configure_installation
    
    # Étapes d'installation
    show_progress 0 10 "Installation"
    
    # 1. Vérifications système
    check_system
    show_progress 1 10 "Installation"
    
    # 2. Installation des dépendances
    install_dependencies
    show_progress 2 10 "Installation"
    
    # 3. Installation de Docker
    install_docker
    show_progress 3 10 "Installation"
    
    # 4. Configuration système
    setup_system
    show_progress 4 10 "Installation"
    
# 5. Préparation des dossiers
    prepare_directories
    show_progress 5 10 "Installation"
    
    # 6. Génération des configurations
    generate_base_docker_compose
    show_progress 6 10 "Installation"
    
    # 7. Configuration de l'administrateur
    create_user "$ADMIN_USER" "$ADMIN_PASSWORD" "$EMAIL" true
    show_progress 7 10 "Installation"
    
    # 8. Configuration des utilisateurs
    for user_info in "${INITIAL_USERS[@]}"; do
        IFS=':' read -r username password email <<< "$user_info"
        create_user "$username" "$password" "$email" false
    done
    show_progress 8 10 "Installation"
    
    # 9. Déploiement des services
    deploy_services
    show_progress 9 10 "Installation"
    
    # 10. Vérifications finales
    setup_quotas_final
    verify_installation
    show_progress 10 10 "Installation"
    
    # Affichage des informations finales
    show_completion_message
}

# Message de fin d'installation
show_completion_message() {
    echo -e "\n${GREEN}Installation terminée avec succès !${NC}"
    echo -e "\nAccédez à votre seedbox via:"
    echo "- Dashboard: https://home.$DOMAIN"
    echo "- Administration: https://traefik.$DOMAIN"
    echo -e "\nIdentifiants administrateur:"
    echo "- Utilisateur: $ADMIN_USER"
    echo "- Mot de passe: (celui que vous avez défini)"
    echo -e "\nPensez à:"
    echo "1. Changer les mots de passe par défaut"
    echo "2. Configurer les quotas si nécessaire"
    echo "3. Vérifier les sauvegardes"
    echo -e "\nLes logs d'installation sont disponibles dans: $INSTALL_DIR/installation.log"
}


# Vérification de l'installation
verify_installation() {
    log "Vérification de l'installation..."
    local errors=0
    local warnings=0
    
    # Vérification des services Docker
    log "Vérification des services Docker..."
    while IFS= read -r line; do
        # Ignorer l'en-tête
        if [[ $line =~ ^NAME || -z $line ]]; then
            continue
        fi
        
        # Extraire le nom du service et son statut
        if [[ $line =~ ^([a-zA-Z0-9_-]+)[[:space:]].+[[:space:]]([A-Za-z][A-Za-z[:space:]()]*)[[:space:]] ]]; then
            local container="${BASH_REMATCH[1]}"
            local status="${BASH_REMATCH[2]}"
            
            # Vérifier si le statut n'est pas "Up"
            if [[ ! $status =~ ^Up ]]; then
                warn "Service $container n'est pas démarré correctement (status: $status)"
                docker logs "$container" | tail -n 50
                ((warnings++))
            fi
        fi
    done < <(docker-compose ps)

    # Vérification des quotas
    if ! quota -v > /dev/null 2>&1; then
        warn "Les quotas ne sont pas correctement configurés"
        ((warnings++))
    fi

    # Vérification des permissions
    local paths=(
        "$INSTALL_DIR"
        "$INSTALL_DIR/traefik"
        "$INSTALL_DIR/authelia"
    )
    
    for path in "${paths[@]}"; do
        if [ ! -w "$path" ]; then
            error "Permissions insuffisantes sur $path"
            ((errors++))
        fi
    done

    # Résumé
    if [ $errors -gt 0 ]; then
        error "$errors erreur(s) détectée(s) lors de la vérification"
        return 1
    elif [ $warnings -gt 0 ]; then
        warn "$warnings avertissement(s) - l'installation est fonctionnelle mais nécessite votre attention"
        return 0
    else
        log "Vérification terminée avec succès"
        return 0
    fi
}

retry_failed_services() {
    log "Tentative de récupération des services en échec..."
    local max_retries=3
    local wait_time=10
    local services_to_retry=()

    # Identifier les services en échec
    while IFS= read -r line; do
        if [[ $line =~ ^([a-zA-Z0-9_-]+)[[:space:]].*Exit ]]; then
            services_to_retry+=("${BASH_REMATCH[1]}")
        fi
    done < <(docker-compose ps)

    if [ ${#services_to_retry[@]} -eq 0 ]; then
        return 0
    fi

    for service in "${services_to_retry[@]}"; do
        log "Tentative de redémarrage de $service..."
        
        for ((i=1; i<=max_retries; i++)); do
            docker-compose restart "$service"
            sleep $wait_time

            if docker-compose ps "$service" | grep -q "Up"; then
                log "Service $service redémarré avec succès"
                break
            else
                if [ $i -eq $max_retries ]; then
                    error "Impossible de redémarrer $service après $max_retries tentatives"
                else
                    warn "Tentative $i/$max_retries échouée pour $service, nouvelle tentative..."
                    wait_time=$((wait_time * 2))
                fi
            fi
        done
    done
}

generate_diagnostic_report() {
    local report_file="/tmp/seedbox_diagnostic_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "=== Rapport de diagnostic Seedbox ==="
        echo "Date: $(date)"
        echo "Version du script: ${SCRIPT_VERSION:-inconnu}"
        echo ""
        
        echo "=== Configuration système ==="
        uname -a
        echo "CPU: $(nproc) cœurs"
        echo "RAM: $(free -h)"
        echo "Espace disque:"
        df -h
        
        echo -e "\n=== Configuration Docker ==="
        docker version
        docker-compose version
        
        echo -e "\n=== Services Docker ==="
        docker-compose ps
        
        echo -e "\n=== Logs des services ==="
        docker-compose ps -q | while read -r container; do
            echo "=== Logs de $container ==="
            docker logs "$container" | tail -n 50
            echo ""
        done
        
        echo -e "\n=== Configuration réseau ==="
        ip addr
        netstat -tulpn
        
        echo -e "\n=== Quotas ==="
        quota -v
        
    } > "$report_file"

    log "Rapport de diagnostic généré: $report_file"
}

main "$@"
