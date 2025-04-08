#!/bin/zsh
# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1,'
WHITE='\033[0;37m'
NC='\033[0m' # No color

# Function to check status
check_status() {
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}$1 Started Successfully!${NC}"
  else
    echo -e "${RED}Problem! Check the log or status of $1.${NC}"
  fi
}

figlet -f slant "Integrated Secuirty Solutions"

#IDS
echo "${BLUE}Starting IDS..."
sudo systemctl start python-ids.service
check_status "IDS"


#IPS
echo "${BLUE}Starting Snort IPS..."
sudo systemctl start snort3.service
check_status "Snort IPS"

#MONGODB
echo "${BLUE}Starting Docker MongoDB..."
docker start mongodb
check_status "mongodb"

#OPENSEARCH
echo "${BLUE}Starting Opensearch... "
sudo systemctl restart opensearch.service
check_status "opensearch.service"

#GRAYLOG
echo "${BLUE}Starting Graylog..."
sudo systemctl start graylog-server.service
check_status "graylog-server.service"

echo -e "${GREEN}${BOLD}ALL COMPONENTS STARTED :)"
