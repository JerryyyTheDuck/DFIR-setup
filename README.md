# Setup Forensics Environment for Ubuntu VM

Due to the python 2.7 cannot install normally due to Canonical has dropped support to Python version 2.x after the long-term Ubuntu. 
The script will automate download some tools and programming language that listed below

### **Minimum Requirements for UBUNTU-WSL** 
- At least 60GB hard drive (WSL cost me around 2x GB of hard disk)
- At least 4-8GB RAM
- Windows Subsystem for Linux version 2
- Ubuntu Distro (Tested with 24.04.1)

### **Minimum Requirements for UBUNTU-VM** (This is still underconstruction for Ubuntu 24.01 VM)

- At least 128GB hard drive (VM)
- At least 4GB RAM (VM) and 8GB RAM (Host)
- Ubuntu Distro (Tested with 24.04.1)

**THOSE SCRIPTS ARE FOR FRESH AND CLEAN UBUNTU INSTALLATION ONLY**

### **How to setup:**

+ First, clone this repository to your local lab
    
    ```sh
    https://github.com/P5ySm1th/DFIR-VM.git
    ```

+ Second, change dir to the repo and change the permission of **install.sh** file.
    
    ```sh
    cd DFIR-VM
    chmod +x install.sh
    ```

+ Last, run the install file:
    
    ```
    sudo ./install.sh
    ```

#### Tools installed in this WSL

## Programming language
- Python 3.12 (default for Ubuntu 24.04.1)
- Python 2.7 
- Go

## Network and Log analyze
- tshark (CLI)
- fakenet-ng 
- chainsaw
- hayabusa

## Cracking and hashing
- john
- hashcat
- yararule
- rockyou.txt
- seclists

## Reverse
- speakeasy
- pycdc
- oletools
- UPX unpacker

## Memory Forensics
- volatility 3
- volatility 2
- Volatility 3 - Autorun
- Volatility 3 - Evtxlog
- Volatility 3 - Notepad
- Volatility 3 - Sticky
- Volatility 3 - Prefetch
- Volatility 3 - Cobaltstrike
- Volatility 3 - Masquerade Process
- avml

## Osint
- holehe
- sherlock
- theHarverster
- ghunt

## Stegno
- steghide
- exiftool
- zsteg
- stegsolve

## misc
- ngrok
- ffuf
- dwarfdump
- openssh-server
- binwalk 
- openvpn
- dos2unix
- gdb