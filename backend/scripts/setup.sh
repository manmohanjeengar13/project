#!/bin/bash

# ============================================
# SQLi Demo Platform - Complete Setup Script
# Version: 3.0.0
# ============================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗ ██████╗ ██╗     ██╗    ██████╗ ███████╗███╗   ███╗   ║
║   ██╔════╝██╔═══██╗██║     ██║    ██╔══██╗██╔════╝████╗ ████║   ║
║   ███████╗██║   ██║██║     ██║    ██║  ██║█████╗  ██╔████╔██║   ║
║   ╚════██║██║▄▄ ██║██║     ██║    ██║  ██║██╔══╝  ██║╚██╔╝██║   ║
║   ███████║╚██████╔╝███████╗██║    ██████╔╝███████╗██║ ╚═╝ ██║   ║
║   ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚═════╝ ╚══════╝╚═╝     ╚═╝   ║
║                                                                   ║
║            SQL Injection Demonstration Platform                  ║
║                   Automated Setup v3.0                           ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${CYAN}🚀 Starting automated setup...${NC}\n"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  echo -e "${YELLOW}⚠️  Warning: Running as root. Consider using a non-root user.${NC}"
fi

# Check Node.js version
echo -e "${BLUE}📦 Checking Node.js version...${NC}"
if ! command -v node &> /dev/null; then
  echo -e "${RED}❌ Node.js is not installed!${NC}"
  echo "Please install Node.js 18+ from https://nodejs.org/"
  exit 1
fi

NODE_VERSION=$(node -v | cut -d 'v' -f 2 | cut -d '.' -f 1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo -e "${RED}❌ Node.js version must be 18 or higher (current: $(node -v))${NC}"
  exit 1
fi
echo -e "${GREEN}✅ Node.js $(node -v) detected${NC}\n"

# Check npm
echo -e "${BLUE}📦 Checking npm...${NC}"
if ! command -v npm &> /dev/null; then
  echo -e "${RED}❌ npm is not installed!${NC}"
  exit 1
fi
echo -e "${GREEN}✅ npm $(npm -v) detected${NC}\n"

# Check MySQL/MariaDB
echo -e "${BLUE}💾 Checking database...${NC}"
if ! command -v mysql &> /dev/null; then
  echo -e "${YELLOW}⚠️  MySQL/MariaDB client not found${NC}"
  echo "Please install MySQL or MariaDB"
  read -p "Continue anyway? (y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
else
  echo -e "${GREEN}✅ MySQL/MariaDB client detected${NC}\n"
fi

# Create project structure
echo -e "${BLUE}📁 Creating project structure...${NC}"
mkdir -p src/{config,core,controllers,services,models,routes,middleware,utils,vulnerabilities,security}
mkdir -p src/vulnerabilities/{sqli,xss,injection,access,auth,business}
mkdir -p database/{migrations,seeds}
mkdir -p uploads/{images,documents,temp}
mkdir -p logs
mkdir -p tests/{unit,integration,security,e2e}
mkdir -p scripts
mkdir -p docs
echo -e "${GREEN}✅ Directory structure created${NC}\n"

# Install dependencies
echo -e "${BLUE}📦 Installing dependencies...${NC}"
if [ -f "package.json" ]; then
  npm install
else
  echo -e "${YELLOW}⚠️  package.json not found, skipping npm install${NC}"
fi
echo -e "${GREEN}✅ Dependencies installed${NC}\n"

# Create .env file
echo -e "${BLUE}⚙️  Creating environment configuration...${NC}"
if [ ! -f ".env" ]; then
  if [ -f ".env.example" ]; then
    cp .env.example .env
    echo -e "${GREEN}✅ .env file created from .env.example${NC}"
  else
    echo -e "${YELLOW}⚠️  .env.example not found${NC}"
  fi
  
  # Generate random secrets
  SESSION_SECRET=$(openssl rand -hex 32 2>/dev/null || date +%s | sha256sum | base64 | head -c 32)
  JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || date +%s | sha256sum | base64 | head -c 32)
  
  # Update .env with generated secrets
  if [ -f ".env" ]; then
    sed -i "s/change-this-to-super-secure-random-64-char-string-in-production/$SESSION_SECRET/g" .env 2>/dev/null || true
    sed -i "s/change-this-to-another-super-secure-random-string/$JWT_SECRET/g" .env 2>/dev/null || true
    echo -e "${GREEN}✅ Random secrets generated${NC}"
  fi
else
  echo -e "${YELLOW}⚠️  .env file already exists, skipping${NC}"
fi
echo

# Database setup
echo -e "${BLUE}💾 Database setup...${NC}"
read -p "Do you want to set up the database now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  read -p "Enter MySQL root password: " -s DB_ROOT_PASS
  echo
  
  read -p "Enter database name (default: sqli_demo_platform): " DB_NAME
  DB_NAME=${DB_NAME:-sqli_demo_platform}
  
  read -p "Enter database user (default: sqli_user): " DB_USER
  DB_USER=${DB_USER:-sqli_user}
  
  read -p "Enter database password: " -s DB_PASS
  echo
  
  echo -e "${BLUE}Creating database...${NC}"
  mysql -u root -p"$DB_ROOT_PASS" << EOF
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SELECT 'Database created successfully' as status;
EOF
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Database created successfully${NC}"
    
    # Update .env with database credentials
    if [ -f ".env" ]; then
      sed -i "s/DB_NAME=.*/DB_NAME=$DB_NAME/g" .env
      sed -i "s/DB_USER=.*/DB_USER=$DB_USER/g" .env
      sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$DB_PASS/g" .env
      echo -e "${GREEN}✅ Database credentials updated in .env${NC}"
    fi
    
    # Run migrations
    if [ -f "database/schema.sql" ]; then
      echo -e "${BLUE}Running database migrations...${NC}"
      mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" < database/schema.sql
      echo -e "${GREEN}✅ Database migrations completed${NC}"
    fi
  else
    echo -e "${RED}❌ Database creation failed${NC}"
  fi
fi
echo

# Set permissions
echo -e "${BLUE}🔐 Setting permissions...${NC}"
chmod -R 755 uploads
chmod -R 755 logs
chmod 600 .env 2>/dev/null || true
echo -e "${GREEN}✅ Permissions set${NC}\n"

# Create systemd service (optional)
echo -e "${BLUE}🔧 System service setup...${NC}"
read -p "Do you want to create a systemd service? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  cat > /tmp/sqli-demo.service << EOF
[Unit]
Description=SQLi Demo Platform
After=network.target mysql.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(which node) src/app.js
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=sqli-demo
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

  sudo mv /tmp/sqli-demo.service /etc/systemd/system/
  sudo systemctl daemon-reload
  echo -e "${GREEN}✅ Systemd service created${NC}"
  echo -e "${CYAN}   To start: sudo systemctl start sqli-demo${NC}"
  echo -e "${CYAN}   To enable on boot: sudo systemctl enable sqli-demo${NC}"
fi
echo

# Final steps
echo -e "${PURPLE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                    🎉 Setup Complete! 🎉                          ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}✅ All setup steps completed!${NC}\n"

echo -e "${CYAN}📝 Next Steps:${NC}"
echo -e "   1. Review and update ${YELLOW}.env${NC} file"
echo -e "   2. Start the server: ${YELLOW}npm run dev${NC}"
echo -e "   3. Visit: ${YELLOW}http://localhost:4000${NC}"
echo -e "   4. Login with: ${YELLOW}admin / admin123${NC}"
echo -e "   5. Read docs: ${YELLOW}http://localhost:4000/api/docs${NC}\n"

echo -e "${CYAN}🔧 Useful Commands:${NC}"
echo -e "   • Start dev server:    ${YELLOW}npm run dev${NC}"
echo -e "   • Start production:    ${YELLOW}npm start${NC}"
echo -e "   • Run tests:           ${YELLOW}npm test${NC}"
echo -e "   • Test attacks:        ${YELLOW}npm run test:security${NC}"
echo -e "   • View logs:           ${YELLOW}tail -f logs/app-*.log${NC}"
echo -e "   • Database backup:     ${YELLOW}npm run backup:db${NC}\n"

echo -e "${CYAN}🎓 Educational Resources:${NC}"
echo -e "   • API Documentation:   ${YELLOW}http://localhost:4000/api/docs${NC}"
echo -e "   • Swagger UI:          ${YELLOW}http://localhost:4000/swagger${NC}"
echo -e "   • Health Check:        ${YELLOW}http://localhost:4000/health${NC}"
echo -e "   • Metrics:             ${YELLOW}http://localhost:4000/metrics${NC}\n"

echo -e "${RED}⚠️  SECURITY WARNING:${NC}"
echo -e "   This application is ${RED}INTENTIONALLY VULNERABLE${NC}"
echo -e "   • ${YELLOW}DO NOT${NC} expose to the internet"
echo -e "   • ${YELLOW}DO NOT${NC} use in production"
echo -e "   • ${YELLOW}DO NOT${NC} store real user data"
echo -e "   • ${YELLOW}FOR EDUCATIONAL PURPOSES ONLY${NC}\n"

echo -e "${GREEN}Happy Learning! 🎓${NC}\n"
