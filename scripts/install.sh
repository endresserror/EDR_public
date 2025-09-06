#!/bin/bash

# IoT EDR System Installation Script

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons."
        echo "Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check OS
    if ! command -v lsb_release &> /dev/null; then
        error "lsb_release not found. Please install lsb-release package."
        exit 1
    fi
    
    OS=$(lsb_release -si)
    VERSION=$(lsb_release -sr)
    
    log "Detected OS: $OS $VERSION"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is required but not installed."
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    log "Python version: $PYTHON_VERSION"
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        error "pip3 is required but not installed."
        exit 1
    fi
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        warning "Node.js not found. Installing Node.js..."
        install_nodejs
    fi
    
    NODE_VERSION=$(node --version)
    log "Node.js version: $NODE_VERSION"
    
    success "System requirements check completed."
}

# Install Node.js
install_nodejs() {
    log "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
}

# Install system dependencies
install_system_dependencies() {
    log "Installing system dependencies..."
    
    sudo apt-get update
    sudo apt-get install -y \
        python3-dev \
        python3-pip \
        python3-venv \
        libpcap-dev \
        tcpdump \
        net-tools \
        iproute2 \
        build-essential \
        curl \
        git \
        sqlite3 \
        nginx \
        supervisor
    
    success "System dependencies installed."
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    sudo mkdir -p /opt/iot-edr/{data,logs,config}
    sudo mkdir -p /var/log/iot-edr
    sudo mkdir -p /etc/iot-edr
    
    # Set permissions
    sudo chown -R $USER:$USER /opt/iot-edr
    sudo chown -R $USER:$USER /var/log/iot-edr
    
    success "Directory structure created."
}

# Install Python backend
install_backend() {
    log "Installing Python backend..."
    
    cd /opt/iot-edr
    
    # Copy backend files
    if [ -d "$HOME/iot-edr/backend" ]; then
        cp -r "$HOME/iot-edr/backend"/* .
    else
        error "Backend source directory not found."
        exit 1
    fi
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install -r requirements.txt
    
    success "Python backend installed."
}

# Install frontend
install_frontend() {
    log "Installing React frontend..."
    
    FRONTEND_DIR="/opt/iot-edr/frontend"
    mkdir -p $FRONTEND_DIR
    
    # Copy frontend files
    if [ -d "$HOME/iot-edr/frontend" ]; then
        cp -r "$HOME/iot-edr/frontend"/* $FRONTEND_DIR/
    else
        error "Frontend source directory not found."
        exit 1
    fi
    
    cd $FRONTEND_DIR
    
    # Install Node.js dependencies and build
    npm install
    npm run build
    
    # Configure nginx
    sudo cp nginx.conf /etc/nginx/sites-available/iot-edr
    sudo ln -sf /etc/nginx/sites-available/iot-edr /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    
    success "React frontend installed."
}

# Create configuration files
create_config() {
    log "Creating configuration files..."
    
    # Copy environment file
    cp .env.example .env
    
    # Generate secret key
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    sed -i "s/your-secret-key-change-this-in-production/$SECRET_KEY/" .env
    
    # Copy configuration to /etc
    sudo cp .env /etc/iot-edr/
    
    success "Configuration files created."
}

# Create systemd services
create_services() {
    log "Creating systemd services..."
    
    # Backend service
    sudo tee /etc/systemd/system/iot-edr-backend.service > /dev/null << EOF
[Unit]
Description=IoT EDR Backend Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/iot-edr
Environment=PATH=/opt/iot-edr/venv/bin
Environment=PYTHONPATH=/opt/iot-edr/src
ExecStart=/opt/iot-edr/venv/bin/python src/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    sudo systemctl daemon-reload
    sudo systemctl enable iot-edr-backend
    
    success "Systemd services created."
}

# Set up firewall
setup_firewall() {
    log "Setting up firewall..."
    
    if command -v ufw &> /dev/null; then
        sudo ufw allow 8000/tcp  # Backend API
        sudo ufw allow 80/tcp    # Frontend
        sudo ufw allow 443/tcp   # HTTPS
        success "Firewall rules added."
    else
        warning "UFW not found. Please configure firewall manually."
    fi
}

# Start services
start_services() {
    log "Starting services..."
    
    # Start backend
    sudo systemctl start iot-edr-backend
    sudo systemctl status iot-edr-backend --no-pager
    
    # Start nginx
    sudo systemctl enable nginx
    sudo systemctl start nginx
    sudo systemctl status nginx --no-pager
    
    success "Services started."
}

# Verify installation
verify_installation() {
    log "Verifying installation..."
    
    # Check backend health
    sleep 5  # Give services time to start
    
    if curl -s http://localhost:8000/health > /dev/null; then
        success "Backend is running and healthy."
    else
        error "Backend health check failed."
    fi
    
    # Check frontend
    if curl -s http://localhost > /dev/null; then
        success "Frontend is accessible."
    else
        error "Frontend accessibility check failed."
    fi
    
    success "Installation verification completed."
}

# Main installation function
main() {
    echo "======================================="
    echo "    IoT EDR System Installation       "
    echo "======================================="
    echo
    
    check_root
    check_requirements
    install_system_dependencies
    create_directories
    install_backend
    install_frontend
    create_config
    create_services
    setup_firewall
    start_services
    verify_installation
    
    echo
    success "IoT EDR System installation completed!"
    echo
    echo "Access the dashboard at: http://localhost"
    echo "API endpoint: http://localhost:8000"
    echo
    echo "System logs: /var/log/iot-edr/"
    echo "Configuration: /etc/iot-edr/"
    echo
    echo "To manage the service:"
    echo "  sudo systemctl start|stop|restart|status iot-edr-backend"
    echo
    warning "Please change the default secret key in /etc/iot-edr/.env"
    warning "Configure your network interface in the configuration file"
}

# Run main function
main "$@"