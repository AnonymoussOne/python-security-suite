# **Auto-Mate: The All-in-One Security Suite**

Auto-Mate is a powerful, secure, and efficient CLI tool built in Python that wraps a full suite of professional penetration testing tools. It provides an interactive REPL shell, a full web-based GUI, and a professional HTML reporting engine.

It is designed to follow the logical flow of a penetration test, from passive reconnaissance to active enumeration and vulnerability identification.

## **🌟 Core Features**

* **Interactive REPL Shell:** Run python3 nscan.py to launch an auto-mate \> shell with history.  
* **Full Web GUI:** Run python3 nscan.py \--gui to launch a local, web-based dashboard.  
* **Professional HTML Reporting:** Add \--format html \-o report.html to *any* command to generate a beautiful, dark-mode HTML report.  
* **Intelligent Automation:**  
  * web command automatically runs wappalyzer, then prompts to run wpscan (for WordPress) or nikto (for generic).  
  * full-scan command chains recon, subdomains, nmap, and web scans for a complete, automated assessment of a domain.  
* **Performance Tuning:**  
  * sys-info command to detect and display local hardware (CPU, RAM, Disk).  
  * \-t, \--threads flag added to nmap and ffuf for manual performance tuning.  
* **Scan Scheduling:** schedule command to create, list, and remove scan jobs directly from the tool.  
* **Secure & Robust:**  
  * Prevents command injection by design (no shell=True).  
  * Validates all input and file paths.  
  * Intelligently creates output directories and expands paths (\~/, $HOME).

## **🛠️ Prerequisites & Installation**

Auto-Mate is a wrapper, so it depends on the tools it runs. You **must** install these external binaries first.

### **1\. Python Libraries (The Easy Part)**

Install the required Python packages (use pip3):

pip install \-r requirements.txt

### **2\. External Binaries (The Main Install)**

#### **On Ubuntu / Debian:**

\# Install core binaries  
sudo apt update  
sudo apt install nmap nikto ffuf nodejs npm ruby-full cron \\  
                 whois dnsutils snmp-check searchsploit enum4linux \\  
                 golang-go

\# Install Go-based tools (like subfinder)  
go install \-v \[github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)  
\# Make sure to move it to your path:  
sudo mv \~/go/bin/subfinder /usr/local/bin/

\# Install npm-based tool  
sudo npm install \-g wappalyzer-cli

\# Install Ruby-based tool  
sudo gem install wpscan

\# Update wpscan database  
wpscan \--update

#### **On macOS / Homebrew:**

\# Install core binaries  
brew install nmap nikto ffuf node ruby whois bind \\  
             snmp-check searchsploit enum4linux-ng subfinder

\# Install npm-based tool  
npm install \-g wappalyzer-cli

\# Install Ruby-based tool  
gem install wpscan

\# Update wpscan database  
wpscan \--update

## **🚀 Getting Started**

1. **Clone the repository:**  
   git clone \https://github.com/AnonymoussOne/python-security-suite.git  
   cd auto-mate

2. Install Python dependencies:  
   (Recommended to use a virtual environment)  
   python3 \-m venv venv  
   source venv/bin/activate  
   pip install \-r requirements.txt

3. **Run the tool\!**  
   python3 nscan.py

## **Modes of Operation**

### **1\. Interactive Shell (Recommended)**

Run the script with no arguments to enter the REPL shell. This is the easiest way to use the tool.

python3 nscan.py

    \_\_ \_  \_ \_\_  | |  \_ \_\_  | |  \_\_ \_  \_\_\_  \_\_\_  
   / \_\` || '\_ \\ | | | '\_ \\ | | / \_\` |/ \_\_|/ \_\_|  
  | (\_| || |\_) || | | |\_) || || (\_| |\\\\\_\_ \\\\\_\_ \\\\  
   \\\_\_,\_|| .\_\_/ |\_| | .\_\_/ |\_| \\\_\_,\_||\_\_\_/|\_\_\_/  
         |\_|         |\_|  
             Security Suite v1.0.0

\[\*\] Welcome to the Auto-Mate interactive shell.  
\[\*\] Type 'help' for commands, 'exit' or 'quit' to leave.  
auto-mate \> 

### **2\. One-Shot Commands**

You can run Auto-Mate commands directly from your terminal. This is useful for scripting.

\# Run a quick nmap scan and save an HTML report  
python3 nscan.py nmap scanme.nmap.org \-p 80,443 \--format html \-o \~/reports/nmap.html

\# Run a full-scan and log to a file  
python3 nscan.py full-scan example.com \-o \~/scan\_logs/example.log

### **3\. Web GUI Mode**

For a simple web-based dashboard, run with the \--gui flag.

python3 nscan.py \--gui

This will automatically open the GUI in your default web browser at http://127.0.0.1:5001.

## **📖 Command Reference**

### **Global Flags**

These flags work before *any* command:

* \-o, \--output \<file\>: Save command output to a file (appends).  
* \--format \<html|text\>: Set output format (default: text).

### **1\. Passive Reconnaissance**

* recon \<domain\>  
  * Runs whois to get domain registration info.  
  * Runs dig ANY \+short to get all common DNS records.  
* subdomains \<domain\>  
  * Uses subfinder to discover all known subdomains.

### **2\. Active Enumeration**

* nmap \<target\> \[nmap\_args\]  
  * Runs **Nmap** with the specified arguments.  
  * **Example:** nmap scanme.nmap.org \-A \-p 1-1000 \-t 100  
* smb \<ip\>  
  * Runs enum4linux-ng with \-A (all) checks.  
  * Finds shares, users, and policies on Windows/Samba systems.  
* snmp \<ip\>  
  * Runs snmp-check with the default public community string.  
  * Dumps all available information from an SNMP service.

### **3\. Web Application**

* web \<url\>  
  * **Intelligent Scan:**  
    1. Runs wappalyzer-cli to identify technologies.  
    2. If **WordPress** is found, prompts to run wpscan.  
    3. If not, prompts to run a generic nikto scan.  
* ffuf \-u \<url\> \-w \<list\> \[options\]  
  * Runs **FFUF** for directory/file fuzzing.  
  * **URL MUST** contain the FUZZ keyword.  
  * **Example:** ffuf \-u http://example.com/FUZZ \-w /usr/share/wordlists/common.txt  
* nikto \<url\>  
  * Runs a nikto scan for common web vulnerabilities.

### **4\. Vulnerability & Exploit**

* search \<query\>  
  * Runs searchsploit to find matching exploits in Exploit-DB.  
  * **Example:** search "WordPress 5.8"

### **5\. Automation**

* full-scan \<domain\>  
  * **The Master Command.** This non-interactive command chains multiple tools:  
    1. recon \<domain\>  
    2. subdomains \<domain\>  
    3. nmap \<subdomain\> \-p quick (for every subdomain found)  
    4. web \<subdomain\> (for every subdomain with web ports)  
  * Ideal for scheduled scans.

### **6\. Utility**

* sys-info  
  * Displays your local system's CPU cores, total RAM, and total Disk space.  
* schedule  
  * Interactive wizard to schedule a new scan via cron.  
* schedule \--list  
  * Lists all scans currently scheduled by Auto-Mate.  
* schedule \--remove  
  * Interactively remove a scheduled scan.  
* help  
  * Shows this help message.  
* exit / quit  
  * Exits the interactive shell.
