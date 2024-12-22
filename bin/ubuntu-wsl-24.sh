#!/bin/bash

RED='\033[0;31m'
NORMAL='\033[0m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'

WORKING_DIR=$1
TMP_DIR="${WORKING_DIR}/.tmp"
LOG_FILE="${WORKING_DIR}/log/Installation.log"
SHELL_RC_FILE="$HOME/.$(echo $SHELL | awk -F '/' '{print $NF}')"rc
PYTHON3_VERSION="$(python3 --version | awk '{print $2}' | cut -d. -f1-2)"
USER=$(whoami)


mkdir -p "$(dirname "$LOG_FILE")" 
touch "$LOG_FILE"
chmod +w "$LOG_FILE"


function writeToLog {
    if [ "$1" -eq 0 ]; then
        echo "$(date): $2 installation successful" >> "$LOG_FILE"
        echo -e "${GREEN}[+] Installing $2 successfully ${NORMAL}"
    else
        echo "$(date): ERROR - $2 installation failed with exit code $1" >> "$LOG_FILE"
        echo -e "${RED}[+] Installing $2 unsuccessfully ${NORMAL}"
    fi
}

function checkPython2(){
    echo -e "${YELLOW}[*] Checking for Python 2${NORMAL}"
    if command -v python2 &> /dev/null; then
        PYTHON2_VERSION=$(python2 --version 2>&1)
        echo -e "${GREEN}[+] Python 2 is installed: ${PYTHON2_VERSION}${NORMAL}"
        return 0
    else
        echo -e "${RED}[-] Python 2 is not installed${NORMAL}"
        echo -e "${YELLOW}[*] Downloading Python 2.7 source${NORMAL}"
        wget -q https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz -P "$TMP_DIR"
        if [ $? -ne 0 ]; then
            echo -e "${RED}[-] Failed to download Python 2.7 source${NORMAL}"
            writeToLog 1 "Download - Python 2.7"
            return 1
        fi
        echo -e "${YELLOW}[*] Successfully download Python 2.7 source${NORMAL}"

        tar -xvf "$TMP_DIR/Python-2.7.18.tgz" -C "$TMP_DIR" > /dev/null 2>&1
        cd "$TMP_DIR/Python-2.7.18"
        if [ $? -ne 0 ]; then
            echo -e "${RED}[-] Failed to change directory to $TMP_DIR/Python-2.7.18${NORMAL}"
            writeToLog 1 "Change directory - Python 2.7"
            return 1
        fi

        echo -e "${YELLOW}[*] Configure Python 2.7 source${NORMAL}"
        ./configure --enable-optimizations > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}[-] Configuration of Python 2.7 failed${NORMAL}"
            writeToLog 1 "Configure - Python 2.7"
            return 1
        fi
        echo -e "${GREEN}[+] Successfully configure Python 2.7 source${NORMAL}"
        
        echo -e "${YELLOW}[*] Make Python 2.7 source${NORMAL}"
        make > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}[-] Building Python 2.7 failed${NORMAL}"
            writeToLog 1 "Build - Python 2.7"
            return 1
        fi
        echo -e "${GREEN}[+] Successfully Make Python 2.7 source${NORMAL}"

        echo -e "${YELLOW}[*] Make install Python 2.7 source${NORMAL}"
        sudo make install > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}[-] Installation of Python 2.7 failed${NORMAL}"
            writeToLog 1 "Install - Python 2.7"
            return 1
        fi
        echo -e "${GREEN}[+] Successfully Make install Python 2.7 source${NORMAL}"
        echo -e "${GREEN}[+] Successfully installed Python 2.7${NORMAL}"
        writeToLog 0 "Install - Python 2.7"
        rm -rf "$TMP_DIR/*"

        
        curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
        sudo python2.7 get-pip.py
        sudo python2.7 -m pip install -U setuptools wheel
    fi
}

function pipInstall(){
    python3 -m pip config set global.break-system-packages true > /dev/null 2>&1
    while read package; do
        echo -e "${YELLOW}[*] Installing library ${package}${NORMAL}"
        python3 -m pip install -U "$package" > /dev/null 2>&1
        writeToLog $? "PIP3 - $package"
    done < $WORKING_DIR/config/requirements3.txt

    while read package; do
        echo -e "${YELLOW}[*] Installing library ${package}${NORMAL}"
        python2.7 -m pip install -U "$package" > /dev/null 2>&1
        writeToLog $? "PIP2 - $package"
    done < $WORKING_DIR/config/requirements2.txt
}

function dependencies {
    APT_PACKAGES=(
        unzip default-jre yara build-essential libdistorm3-dev libnetfilter-queue-dev
        libssl-dev libyara-dev libcapstone-dev capstone-tool python3-dev
        libpython3-dev python3-pip python3-setuptools python3-wheel python${PYTHON3_VERSION}-venv
        libncursesw5-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev 
        cmake make clang
    )

    for package in "${APT_PACKAGES[@]}"; do
        echo -e "${YELLOW}[*] Installing package ${package}${NORMAL}"
        sudo apt install -y "$package" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}[-] Failed to install ${package}${NORMAL}"
            writeToLog 1 "APT - $package"
        else
            writeToLog 0 "APT - $package"
        fi
    done

    checkPython2
    pipInstall
    sudo apt-get update -y > /dev/null 2>&1 && sudo apt-get upgrade -y > /dev/null 2>&1
}

function memoryForensics(){
    echo -e "${YELLOW}[*] Installing Volatility 3${NORMAL}"
    python3 -m pip install -U git+https://github.com/volatilityfoundation/volatility3.git > /dev/null 2>&1
    writeToLog $? "Volatility 3"

    echo -e "${YELLOW}[*] Installing Volatility 2${NORMAL}"
    python2.7 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git > /dev/null 2>&1
    writeToLog $? "Volatility 2"

    echo -e "${YELLOW}[*] Installing Volatility 3 Plugins${NORMAL}"
    wget -q https://raw.githubusercontent.com/Telindus-CSIRT/volatility3-autoruns/refs/heads/main/autorun.py -P /home/$SUDO_USER/.local/lib/python${PYTHON3_VERSION}/site-packages/volatility3/framework/plugins/windows/
    writeToLog $? "Volatility 3 - Autorun"

    wget -q https://raw.githubusercontent.com/spitfirerxf/vol3-plugins/refs/heads/main/evtxlog.py -P /home/$SUDO_USER/.local/lib/python${PYTHON3_VERSION}/site-packages/volatility3/framework/plugins/windows/
    writeToLog $? "Volatility 3 - Evtxlog"

    wget -q https://raw.githubusercontent.com/spitfirerxf/vol3-plugins/refs/heads/main/notepad.py -P /home/$SUDO_USER/.local/lib/python${PYTHON3_VERSION}/site-packages/volatility3/framework/plugins/windows/
    writeToLog $? "Volatility 3 - Notepad"

    wget -q https://raw.githubusercontent.com/spitfirerxf/vol3-plugins/refs/heads/main/sticky.py -P /home/$SUDO_USER/.local/lib/python${PYTHON3_VERSION}/site-packages/volatility3/framework/plugins/windows/
    writeToLog $? "Volatility 3 - Sticky"

    wget -q https://raw.githubusercontent.com/forensicxlab/volatility3_plugins/refs/heads/main/prefetch.py -P /home/$SUDO_USER/.local/lib/python${PYTHON3_VERSION}/site-packages/volatility3/framework/plugins/windows/
    writeToLog $? "Volatility 3 - Prefetch"

    wget -q https://raw.githubusercontent.com/kevthehermit/volatility_plugins/refs/heads/main/vol3/cobaltstrike/cobaltstrike.py -P /home/$SUDO_USER/.local/lib/python${PYTHON3_VERSION}/site-packages/volatility3/framework/plugins/windows/
    writeToLog $? "Volatility 3 - Cobaltstrike"

    wget -q https://raw.githubusercontent.com/memoryforensics1/Volatility.PE-Shellcode/refs/heads/main/masqueradeprocess.py -P /home/$SUDO_USER/.local/lib/python${PYTHON3_VERSION}/site-packages/volatility3/framework/plugins/windows/
    writeToLog $? "Volatility 3 - Masquerade Process"

    echo -e "${YELLOW}[*] Installing Volatility 2 Plugins${NORMAL}"
    git clone https://github.com/superponible/volatility-plugins.git $TMP_DIR/volatility2-plugins > /dev/null 2>&1
    mv $TMP_DIR/volatility2-plugins/*.py /home/$SUDO_USER/.local/lib/python2.7/site-packages/volatility/plugins/linux/ > /dev/null 2>&1
    rm -rf $TMP_DIR/volatility2-plugins
    writeToLog $? "Volatility 2 - Install plugin successfully"

    echo -e "${YELLOW}[*] Installing Memory extractor${NORMAL}"
    mkdir -p /home/$SUDO_USER/tools/memory-extractor
    wget -q https://github.com/microsoft/avml/releases/download/v0.14.0/avml -P /home/$SUDO_USER/tools/memory-extractor
    chmod +x /home/$SUDO_USER/tools/memory-extractor/avml
    writeToLog $? "AVML - Install successfully"
}

function network(){
    echo -e "${YELLOW}[*] Installing tshark${NORMAL}"
    sudo apt-get install -y tshark > /dev/null 2>&1
    writeToLog $? "APT - tshark"

    echo -e "${YELLOW}[*] Installing flare-fakenet-ng${NORMAL}"
    git clone https://github.com/P5ySm1th/fakenet-ng-py3.12.git $TMP_DIR/fakenet-ng > /dev/null 2>&1
    pip3 install $TMP_DIR/fakenet-ng > /dev/null 2>&1
    writeToLog $? "Fakenet-ng - Install successfully"   

    echo -e "${YELLOW}[*] Installing chainsaw${NORMAL}"
    wget -q https://github.com/WithSecureLabs/chainsaw/releases/download/v2.10.1/chainsaw_x86_64-unknown-linux-gnu.tar.gz -P /home/$SUDO_USER/tools/chainsaw
    tar -xf /home/$SUDO_USER/tools/chainsaw/chainsaw_x86_64-unknown-linux-gnu.tar.gz -C /home/$SUDO_USER/tools/chainsaw > /dev/null 2>&1
    cp /home/$SUDO_USER/tools/chainsaw/chainsaw/chainsaw /usr/bin/chainsaw && sudo chmod +x /usr/bin/chainsaw
    writeToLog $? "Chainsaw - Install successfully"

    echo -e "${YELLOW}[*] Installing hayabusa${NORMAL}"
    wget -q https://github.com/Yamato-Security/hayabusa/releases/download/v2.19.0/hayabusa-2.19.0-lin-x64-gnu.zip -P /home/$SUDO_USER/tools/hayabusa
    unzip /home/$SUDO_USER/tools/hayabusa/hayabusa-2.19.0-lin-x64-gnu.zip -d /home/$SUDO_USER/tools/hayabusa > /dev/null 2>&1
    rm -rf /home/$SUDO_USER/tools/hayabusa/hayabusa-2.19.0-lin-x64-gnu.zip 
    mv /home/$SUDO_USER/tools/hayabusa/hayabusa-2.19.0-lin-x64-gnu /home/$SUDO_USER/tools/hayabusa/hayabusa
    sudo cp /home/$SUDO_USER/tools/hayabusa/hayabusa /usr/bin/hayabusa && sudo chmod +x /usr/bin/hayabusa
    writeToLog $? "Hayabusa - Install successfully"
}


function reverse(){
    echo -e "${YELLOW}[*] Installing speakeasy${NORMAL}"
    git clone https://github.com/mandiant/speakeasy.git $TMP_DIR/speakeasy > /dev/null 2>&1
    pip3 install $TMP_DIR/speakeasy > /dev/null 2>&1
    writeToLog $? "speakeasy - Install successfully"   

    echo -e "${YELLOW}[*] Installing pycdc${NORMAL}"
    git clone https://github.com/zrax/pycdc.git $TMP_DIR/pycdc > /dev/null 2>&1
    cd $TMP_DIR/pycdc && cmake -DCMAKE_BUILD_TYPE="${PREFIX}" . > /dev/null 2>&1 && make > /dev/null 2>&1 && make install > /dev/null 2>&1
    writeToLog $? "pycdc - Install successfully"

    echo -e "${YELLOW}[*] Installing oletools${NORMAL}"
    git clone https://github.com/decalage2/oletools.git $TMP_DIR/oletools > /dev/null 2>&1
    pip3 install $TMP_DIR/oletools > /dev/null 2>&1
    writeToLog $? "oletools - Install successfully"

    echo -e "${YELLOW}[*] Installing UPX${NORMAL}"
    wget -q https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-amd64_linux.tar.xz -P /home/$SUDO_USER/tools/upx
    tar -xf /home/$SUDO_USER/tools/upx/upx-4.2.4-amd64_linux.tar.xz -C /home/$SUDO_USER/tools/upx > /dev/null 2>&1
    rm -rf /home/$SUDO_USER/tools/upx/upx-4.2.4-amd64_linux.tar.xz
    sudo cp /home/$SUDO_USER/tools/upx/upx-4.2.4-amd64_linux/upx /usr/bin/upx && sudo chmod +x /usr/bin/upx
    writeToLog $? "UPX - Install successfully"


}

function stego(){
    echo -e "${YELLOW}[*] Installing steghide${NORMAL}"
    sudo apt-get install -y steghide > /dev/null 2>&1
    writeToLog $? "APT - steghide"

    echo -e "${YELLOW}[*] Installing exiftool${NORMAL}"
    sudo apt-get install -y exiftool > /dev/null 2>&1
    writeToLog $? "APT - exiftool"

    echo -e "${YELLOW}[*] Installing zsteg${NORMAL}"
    sudo gem install zsteg > /dev/null 2>&1
    writeToLog $? "zsteg - Install successfully"

    echo -e "${YELLOW}[*] Installing stegseek${NORMAL}"
    wget -q https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb -P /home/$SUDO_USER/tools/stegseek
    chmod +x /home/$SUDO_USER/tools/stegseek/stegseek_0.6-1.deb
    sudo apt-get install -y ./stegseek_0.6-1.deb
    writeToLog $? "stegseek - Install successfully"

    echo -e "${YELLOW}[*] Installing stegsolve${NORMAL}"
    wget -q http://www.caesum.com/handbook/Stegsolve.jar -P /home/$SUDO_USER/tools/stegsolve
    chmod +x /home/$SUDO_USER/tools/stegsolve/Stegsolve.jar
    writeToLog $? "stegsolve - Install successfully"
}

function osint(){
    echo -e "${YELLOW}[*] Installing holehe${NORMAL}"
    git clone https://github.com/megadose/holehe.git $TMP_DIR/holehe > /dev/null 2>&1
    pip3 install $TMP_DIR/holehe > /dev/null 2>&1
    writeToLog $? "holehe - Install successfully"

    echo -e "${YELLOW}[*] Installing sherlock${NORMAL}"
    sudo apt install sherlock > /dev/null 2>&1
    writeToLog $? "sherlock - Install successfully"

    echo -e "${YELLOW}[*] Installing theHarvester${NORMAL}"
    git clone https://github.com/laramies/theHarvester $TMP_DIR/theHarvester > /dev/null 2>&1
    pip3 install -r $TMP_DIR/theHarvester/requirements.txt > /dev/null 2>&1
    chmod +x $TMP_DIR/theHarvester/theHarvester.py
    sudo cp $TMP_DIR/theHarvester/theHarvester.py /usr/bin
    writeToLog $? "theHarvester - Install successfully"

    echo -e "${YELLOW}[*] Installing ghunt${NORMAL}"
    pip3 install pipx > /dev/null 2>&1
    pipx ensurepath > /dev/null 2>&1
    pipx install ghunt > /dev/null 2>&1
    writeToLog $? "ghunt - Install successfully"
}

function wordlistsAndCracking(){
    echo -e "${YELLOW}[*] Installing john${NORMAL}"
    sudo apt-get install john -y > /dev/null 2>&1
    writeToLog $? "john - Install successfully"

    echo -e "${YELLOW}[*] Installing hashcat${NORMAL}"
    sudo apt install -y hashcat > /dev/null 2>&1
    writeToLog $? "APT - hashcat"

    echo -e "${YELLOW}[*] Installing yara rule${NORMAL}"
    git clone https://github.com/Yara-Rules/rules.git $TMP_DIR/wordlist/yara-rules > /dev/null 2>&1
    writeToLog $? "Yara Rules - Install successfully"

    echo -e "${YELLOW}[*] Installing rockyou wordlist${NORMAL}"
    git clone https://github.com/3ndG4me/KaliLists.git $TMP_DIR/wordlist/rockyou > /dev/null 2>&1
    gunzip $TMP_DIR/wordlist/rockyou/rockyou.txt.gz
    echo export ROCKYOU="$TMP_DIR/wordlist/rockyou/rockyou.txt" >> /home/$SUDO_USER/.profile
    writeToLog $? "Rockyou - Install successfully"

    echo -e "${YELLOW}[*] Installing SecLists${NORMAL}"
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git $TMP_DIR/wordlist/SecLists
    echo export SECLISTS="$TMP_DIR/wordlist/SecLists" >> /home/$SUDO_USER/.profile
    writeToLog $? "SecLists - Install successfully"
}

function misc(){
    echo -e "${YELLOW}[*] Installing ngrok${NORMAL}"
    sudo snap install ngrok > /dev/null 2>&1
    writeToLog $? "ngrok - Install successfully"

    echo -e "${YELLOW}[*] Installing Golang${NORMAL}"
    GO_VERSION="1.16.7"
    GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
    GO_INSTALL_DIR="/usr/local"
    GO_DOWNLOAD_DIR="/home/$SUDO_USER/tools/golang"

    sudo mkdir -p "$GO_DOWNLOAD_DIR"

    sudo wget -q "https://golang.org/dl/${GO_TARBALL}" -P "$GO_DOWNLOAD_DIR"
    if [ $? -eq 0 ]; then
        sudo tar -xvzf "${GO_DOWNLOAD_DIR}/${GO_TARBALL}" -C "$GO_INSTALL_DIR" > /dev/null 2>&1
        sudo rm -rf "${GO_DOWNLOAD_DIR}/${GO_TARBALL}"

        if ! grep -q "/usr/local/go/bin" "/home/$SUDO_USER/.profile"; then
            echo "export PATH=\$PATH:/usr/local/go/bin" | sudo tee -a "/home/$SUDO_USER/.profile" > /dev/null
            writeToLog 0 "Golang - Installed successfully"
        else
            writeToLog 0 "Golang - Already installed and PATH updated"
        fi
    else
        writeToLog 1 "Golang - Failed to download"
    fi
    source "/home/$SUDO_USER/.profile"
    go version > /dev/null 2>&1

    echo -e "${YELLOW}[*] Installing ffuf${NORMAL}"
    go install github.com/ffuf/ffuf/v2@latest > /dev/null 2>&1
    writeToLog $? "ffuf - Install successfully"


    APT_PACKAGES=(
        dwarfdump openssh-server net-tools 
        binwalk openvpn dos2unix gdb
    )
    for package in "${APT_PACKAGES[@]}"; do
        echo -e "${YELLOW}[*] Installing package ${package}${NORMAL}"
        sudo apt install -y $package > /dev/null 2>&1
        writeToLog $? "APT - $package"
    done
}

function zsh(){
    echo -e "${YELLOW}[*] Installing zsh${NORMAL}"
    sudo apt install zsh -y > /dev/null 2>&1
    writeToLog $? "APT - zsh"

    echo -e "${YELLOW}[*] Changing default shell to zsh${NORMAL}"
    chsh -s $(which zsh)
    writeToLog $? "Change default shell - zsh"

    echo -e "${YELLOW}[*] Installing oh-my-zsh${NORMAL}"
    bash -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
    writeToLog $? "curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh"

    echo -e "${YELLOW}[*] Installing zsh plugins${NORMAL}"
    git clone https://github.com/zsh-users/zsh-autosuggestions.git $ZSH_CUSTOM/plugins/zsh-autosuggestions
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting
    sed -i "/^plugins=/cplugins=(git aliases colorize colored-man-pages copypath encode64 zoxide zsh-autosuggestions zsh-syntax-highlighting)" ~/.zshrc
    writeToLog $? "zsh plugins - Install successfully"
}

function main(){
    echo -e "${YELLOW}[*] Update and Upgrade dependencies${NORMAL}"
    sudo apt-get update -y > /dev/null 2>&1 && sudo apt-get upgrade -y > /dev/null 2>&1
    writeToLog $? "APT - Update and Upgrade"

    dependencies
    memoryForensics
    network
    reverse
    misc
    stego
    wordlistsAndCracking
    osint
    zsh

    cp -r $TMP_DIR/* /home/$SUDO_USER/tools
}

main