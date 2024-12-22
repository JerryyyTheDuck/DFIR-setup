#!/bin/bash

RED='\033[0;31m'
NORMAL='\033[0m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'

WORKING_DIR=$(pwd)
DISTRO_VER=$(lsb_release -rs)

echo -e "${GREEN}[+] This script is based on tr4c3datr4il ForVM script${NORMAL}"
echo -e "${GREEN}[+] If there are any issues, please contact via https://github.com/P5ySm1th/DFIR-VM/issues${NORMAL}"
echo -e "${GREEN}[+] Checking for root privileges${NORMAL}"
echo -e "${YELLOW}[*] Before install, after install zsh, please prompt "exit" for the next configuration stage${NORMAL}"
echo -e "${YELLOW}[*] Do you wish to continue? (y/n)${NORMAL}"
read -r LMAO
case "$LMAO" in
    [Nn]*)
        echo -e "${RED}[-] Exiting as per user request.${NORMAL}"
        exit 1
        ;;
    [Yy]*)
        echo -e "${GREEN}[+] Proceeding with setup${NORMAL}"
        ;;
    *)
        echo -e "${RED}[-] Invalid input. Exiting.${NORMAL}"
        exit 1
        ;;
esac

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[-] Please run as root or sudo${NORMAL}"
    exit 1
fi

if [[ -f "/etc/wsl.conf" ]]; then
    if [[ "$DISTRO_VER" == "24.04" ]]; then
        echo -e "${GREEN}[+] Setting up forensics environment for WSL version ${DISTRO_VER}${NORMAL}"
        chmod +x ./bin/ubuntu-wsl-24.sh
        bash ./bin/ubuntu-wsl-24.sh $WORKING_DIR
    else
        echo -e "${RED}[-] This setup is intended for WSL version 24.04${NORMAL}"
        echo -e "${YELLOW}[*] Do you wish to continue? (y/n)${NORMAL}"
        read -r CONTINUE
        case "$CONTINUE" in
            [Nn]*)
                echo -e "${RED}[-] Exiting as per user request.${NORMAL}"
                exit 1
                ;;
            [Yy]*)
                echo -e "${GREEN}[+] Proceeding with setup for WSL version ${DISTRO_VER}${NORMAL}"
                # Place setup script for other WSL versions here
                ;;
            *)
                echo -e "${RED}[-] Invalid input. Exiting.${NORMAL}"
                exit 1
                ;;
        esac
    fi
else
    echo -e "${GREEN}[+] Setting up forensics environment for Ubuntu ${DISTRO_VER}${NORMAL}"
fi
