#!/usr/bin/env python3

"""
Auto-Mate Security Suite v1.0.0
A Python-based, all-in-one CLI and Web GUI for network reconnaissance
and vulnerability scanning.

This tool wraps and orchestrates a suite of professional security tools:
nmap, nikto, wpscan, ffuf, subfinder, searchsploit, enum4linux-ng,
snmp-check, whois, and dig.
"""

import os
import sys
import subprocess
import shlex
import re
import json
import webbrowser
import threading
import socket
import psutil
from datetime import datetime
from crontab import CronTab
from urllib.parse import urlparse
from pathlib import Path

# --- External Dependencies ---
try:
    from flask import Flask, render_template, request, jsonify, send_from_directory
    from jinja2 import Environment, FileSystemLoader, Template, escape
    import colorama
    from colorama import Fore, Style
except ImportError as e:
    print(f"Error: Missing required Python package. Please install '{e.name}'.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

# --- Tool Configuration ---
VERSION = "v1.0.0"
APP_NAME = "Auto-Mate"
GUI_PORT = 5001
LOG_FILE = Path.home() / "auto-mate.log"

# --- ASCII Banner ---
BANNER = f"""{Fore.CYAN}
    __ _  _ __  | |  _ __  | |  __ _  ___  ___
   / _` || '_ \ | | | '_ \ | | / _` |/ __|/ __|
  | (_| || |_) || | | |_) || || (_| |\\__ \\__ \\
   \__,_|| .__/ |_| | .__/ |_| \__,_||___/|___/
         |_|         |_|
{Style.RESET_ALL}
             Security Suite {VERSION}
"""

# --- Helper Functions ---

def print_banner():
    """Prints the main tool banner."""
    print(BANNER)

def c_print(text, color=Fore.GREEN, bright=Style.BRIGHT):
    """Prints colored text."""
    print(f"{bright}{color}{text}{Style.RESET_ALL}")

def c_error(text):
    """Prints an error message."""
    print(f"{Style.BRIGHT}{Fore.RED}[-] Error: {text}{Style.RESET_ALL}")

def c_warn(text):
    """Prints a warning message."""
    print(f"{Style.BRIGHT}{Fore.YELLOW}[!] Warning: {text}{Style.RESET_ALL}")

def c_success(text):
    """Prints a success message."""
    print(f"{Style.BRIGHT}{Fore.GREEN}[+] {text}{Style.RESET_ALL}")

def c_info(text):
    """Prints an info message."""
    print(f"{Style.BRIGHT}{Fore.CYAN}[*] {text}{Style.RESET_ALL}")

def c_title(text):
    """Prints a title section."""
    print(f"\n{Style.BRIGHT}{Fore.MAGENTA}--- {text} ---{Style.RESET_ALL}")

def check_tool(name):
    """Check if a binary is installed and executable."""
    c_info(f"Checking for tool: {name}...")
    try:
        # Use 'which' or 'where' for a lightweight check first
        checker_cmd = "where" if os.name == 'nt' else "which"
        subprocess.run([checker_cmd, name], capture_output=True, text=True, check=True, timeout=5)
        c_success(f"Found {name}.")
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        c_error(f"Tool '{name}' not found or not in your system's PATH.")
        c_warn(f"Please install '{name}' and ensure it's in your PATH.")
        return False

def validate_path(path_str, check_exists=False, check_writable_dir=False, create_dir=False):
    """
    Validates a file path.
    - Expands '~' and environment variables.
    - Checks if it exists (if check_exists=True).
    - Checks if the parent directory is writable (if check_writable_dir=True).
    - Creates the parent directory (if create_dir=True).
    Returns a resolved Path object or None.
    """
    try:
        # Expand user and variables
        expanded_path_str = os.path.expandvars(os.path.expanduser(path_str))
        p = Path(expanded_path_str).resolve()

        if create_dir:
            # We want to create the parent directory of the *output file*
            p.parent.mkdir(parents=True, exist_ok=True)
        
        if check_writable_dir:
            if not os.access(p.parent, os.W_OK):
                c_error(f"Directory is not writable: {p.parent}")
                return None
        
        if check_exists:
            if not p.exists():
                c_error(f"File/Directory does not exist: {p}")
                return None
            if not os.access(p, os.R_OK):
                c_error(f"File is not readable: {p}")
                return None
        
        return p
    except Exception as e:
        c_error(f"Invalid path '{path_str}': {e}")
        return None

def write_output(output_file_path, format, content, title):
    """Writes content to the output file in the specified format."""
    if not output_file_path:
        return

    c_info(f"Writing output to {output_file_path}...")
    try:
        if format == 'html':
            html_content = generate_html_report(content, title)
            with open(output_file_path, "a", encoding="utf-8") as f:
                f.write(html_content + "\n<hr>\n")
        else: # 'text'
            with open(output_file_path, "a", encoding="utf-8") as f:
                f.write(f"--- {title} ---\n")
                f.write(content + "\n\n")
        c_success(f"Successfully wrote output to {output_file_path}")
    except Exception as e:
        c_error(f"Failed to write to output file: {e}")

def run_command(command, title, output_file=None, output_format='text'):
    """
    Runs a shell command, streams its output, and handles errors.
    Returns the captured output as a string.
    """
    c_title(f"Running: {title}")
    c_info(f"Command: {' '.join(command)}")
    
    full_output = ""
    try:
        # Start the subprocess
        process = subprocess.Popen(command, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.STDOUT, 
                                   text=True, 
                                   encoding='utf-8', 
                                   errors='replace')

        # Stream the output
        while True:
            line = process.stdout.readline()
            if not line:
                break
            line = line.strip()
            print(line)
            full_output += line + "\n"
        
        process.wait()
        
        if process.returncode != 0:
            c_warn(f"{title} finished with a non-zero exit code ({process.returncode}).")
        
        c_success(f"{title} complete.")
        
        write_output(output_file, output_format, full_output, title)
        return full_output

    except FileNotFoundError:
        c_error(f"Command not found: {command[0]}. Please ensure it's installed and in your PATH.")
        return None
    except Exception as e:
        c_error(f"An error occurred while running '{title}': {e}")
        return None

def get_user_confirmation(prompt):
    """Gets a 'y/n' confirmation from the user."""
    while True:
        response = input(f"{Style.BRIGHT}{Fore.YELLOW}[?] {prompt} (y/n): {Style.RESET_ALL}").strip().lower()
        if response == 'y':
            return True
        if response == 'n':
            return False
        c_warn("Please enter 'y' or 'n'.")

def parse_nmap_threads(thread_arg):
    """Converts a thread count to an Nmap -T flag."""
    try:
        threads = int(thread_arg)
        if threads <= 10: return "-T2" # Slow, for IDS evasion
        if threads <= 50: return "-T3" # Normal
        if threads <= 150: return "-T4" # Fast
        return "-T5" # Insane
    except ValueError:
        return "-T4" # Default

# --- HTML Reporting ---
HTML_TEMPLATE_STR = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - Auto-Mate Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: #121212;
            color: #e0e0e0;
            margin: 0;
            padding: 20px;
            font-size: 16px;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background-color: #1e1e1e;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.5);
            overflow: hidden;
            border: 1px solid #333;
        }
        .header {
            background-color: #333;
            color: #00e5ff;
            padding: 20px;
            border-bottom: 2px solid #00e5ff;
        }
        .header h1 {
            margin: 0;
            font-size: 2em;
        }
        .header p {
            margin: 5px 0 0;
            font-size: 1.1em;
            color: #b0b0b0;
        }
        .report-section {
            padding: 20px;
            border-bottom: 1px solid #333;
        }
        .report-section:last-child {
            border-bottom: none;
        }
        .report-section h2 {
            font-size: 1.8em;
            color: #00e5ff;
            margin-top: 0;
            border-bottom: 2px solid #444;
            padding-bottom: 5px;
        }
        pre {
            background-color: #272727;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: "Courier New", Courier, monospace;
            font-size: 0.95em;
            color: #d0d0d0;
            border: 1px solid #444;
        }
        .footer {
            text-align: center;
            padding: 15px;
            font-size: 0.9em;
            color: #777;
            background-color: #222;
            border-top: 1px solid #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Auto-Mate Security Report</h1>
            <p>Generated: {{ timestamp }}</p>
        </div>
        <div class="report-section">
            <h2>{{ title }}</h2>
            <pre>{{ content | escape }}</pre>
        </div>
        <div class="footer">
            Auto-Mate v{{ version }}
        </div>
    </div>
</body>
</html>
"""
HTML_TEMPLATE = Template(HTML_TEMPLATE_STR)

def generate_html_report(content, title):
    """Generates a single, self-contained HTML report."""
    return HTML_TEMPLATE.render(
        title=title,
        content=content,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        version=VERSION
    )

# --- Tool Commands ---

class ToolCommands:
    def __init__(self, output_file=None, output_format='text'):
        self.output_file = output_file
        self.output_format = output_format
        self.tools_checked = False

    def check_all_tools(self):
        """Checks for all critical external binaries."""
        if self.tools_checked:
            return
        c_title("Checking System Tools")
        tools = ["nmap", "nikto", "ffuf", "wpscan", "wappalyzer", 
                 "subfinder", "searchsploit", "enum4linux-ng", 
                 "snmp-check", "whois", "dig"]
        all_ok = True
        for tool in tools:
            if not check_tool(tool):
                all_ok = False
        
        if all_ok:
            c_success("All tools found.")
        else:
            c_error("Some tools are missing. Please install them to use all features.")
        self.tools_checked = True

    def _validate_output_args(self, args):
        """Helper to validate output file paths."""
        output_file = None
        output_format = self.output_format

        # Check for global flags if args is a namespace
        if hasattr(args, 'output') and args.output:
            output_file = validate_path(args.output, create_dir=True)
            if not output_file:
                return None, args.format
            
        if hasattr(args, 'format') and args.format:
             output_format = args.format
        
        # Override with REPL defaults if not present
        if not output_file:
             output_file = self.output_file
        if not output_format:
             output_format = self.output_format
             
        return output_file, output_format

    def do_sys_info(self, args):
        """Display local system information (CPU, Memory, Disk)."""
        c_title("System Information")
        try:
            # CPU
            cpu_cores = os.cpu_count()
            c_success(f"CPU Cores: {cpu_cores}")
            
            # Memory
            mem = psutil.virtual_memory()
            mem_total_gb = round(mem.total / (1024**3), 2)
            c_success(f"Total RAM: {mem_total_gb} GB")
            
            # Disk
            disk = psutil.disk_usage('/')
            disk_total_gb = round(disk.total / (1024**3), 2)
            c_success(f"Total Disk: {disk_total_gb} GB")

        except Exception as e:
            c_error(f"Could not retrieve system info: {e}")

    def do_nmap(self, args):
        """Run an Nmap scan."""
        output_file, output_format = self._validate_output_args(args)
        
        if not args.target:
            c_error("Nmap command requires a target.")
            return

        # Basic input validation for target
        target_regex = re.compile(r"^[a-zA-Z0-9\.\-/\s]+$")
        if not target_regex.match(args.target):
            c_error("Invalid target format.")
            return

        command = ["nmap", args.target]
        
        # Handle Nmap args. We split them to be safe.
        nmap_args = shlex.split(' '.join(args.nmap_args))

        # Check for root-requiring scans
        root_scans = ["-sS", "-O"]
        if any(flag in nmap_args for flag in root_scans) and os.geteuid() != 0:
            c_warn("Scans like -sS (Stealth) or -O (OS) work best with sudo privileges.")

        # Handle threads
        if args.threads:
            nmap_timing = parse_nmap_threads(args.threads)
            command.append(nmap_timing)
        
        command.extend(nmap_args)
        
        return run_command(command, "Nmap Scan", output_file, output_format)

    def do_nikto(self, args):
        """Run a Nikto web vulnerability scan."""
        output_file, output_format = self._validate_output_args(args)

        if not args.url:
            c_error("Nikto command requires a URL.")
            return

        # Basic validation
        url_regex = re.compile(r"^https?://[a-zA-Z0-9\.\-]+(:[0-9]+)?(/.*)?$")
        if not url_regex.match(args.url):
            c_error("Invalid URL format. Must start with http:// or https://")
            return

        command = ["nikto", "-h", args.url]
        command.extend(args.nikto_args)
        return run_command(command, "Nikto Scan", output_file, output_format)

    def do_ffuf(self, args):
        """Run an FFUF web fuzzing scan."""
        output_file, output_format = self._validate_output_args(args)

        if not args.url or not args.wordlist:
            c_error("FFUF command requires a URL (-u) and a wordlist (-w).")
            return
        
        if "FUZZ" not in args.url:
            c_error("URL must contain the 'FUZZ' keyword.")
            return

        # Validate wordlist exists and is readable
        wordlist_path = validate_path(args.wordlist, check_exists=True)
        if not wordlist_path:
            return

        command = ["ffuf", "-u", args.url, "-w", str(wordlist_path)]

        if args.extensions:
            ext_regex = re.compile(r"^[a-zA-Z0-9\.,]+$")
            if ext_regex.match(args.extensions):
                command.extend(["-e", args.extensions])
            else:
                c_error("Invalid extensions format.")
                return

        if args.match_codes:
            code_regex = re.compile(r"^[0-9,]+$")
            if code_regex.match(args.match_codes):
                command.extend(["-mc", args.match_codes])
            else:
                c_error("Invalid match codes format.")
                return

        if args.filter_codes:
            code_regex = re.compile(r"^[0-9,]+$")
            if code_regex.match(args.filter_codes):
                command.extend(["-fc", args.filter_codes])
            else:
                c_error("Invalid filter codes format.")
                return

        if args.threads:
            thread_regex = re.compile(r"^[0-9]+$")
            if thread_regex.match(args.threads):
                command.extend(["-t", args.threads])
            else:
                c_error("Invalid threads format.")
                return

        return run_command(command, "FFUF Scan", output_file, output_format)

    def do_web(self, args):
        """Run a smart web scan (Wappalyzer + WPScan/Nikto)."""
        output_file, output_format = self._validate_output_args(args)
        
        if not args.url:
            c_error("Web scan requires a URL.")
            return
        
        # 1. Run Wappalyzer
        wappalyzer_output = run_command(
            ["wappalyzer-cli", args.url], 
            "Technology Detection (Wappalyzer)", 
            output_file, 
            output_format
        )
        
        if wappalyzer_output is None:
            c_error("Wappalyzer failed, aborting web scan.")
            return

        # 2. Check for WordPress
        is_wordpress = False
        try:
            # Wappalyzer-cli output is JSON
            tech_data = json.loads(wappalyzer_output)
            # Wappalyzer-cli v6+ structure
            if "technologies" in tech_data:
                is_wordpress = any(tech.get('name') == 'WordPress' for tech in tech_data['technologies'])
        except json.JSONDecodeError:
            # Fallback for older versions or non-json output
            if "wordpress" in wappalyzer_output.lower():
                is_wordpress = True

        # 3. Interactive Prompt
        if is_wordpress:
            if get_user_confirmation("WordPress detected. Run specific WPScan vulnerability scan?"):
                self.run_wpscan(args.url, output_file, output_format)
        else:
            if get_user_confirmation("No WordPress. Run generic Nikto vulnerability scan?"):
                self.run_nikto(args.url, output_file, output_format)

    def run_nikto(self, url, output_file, output_format):
        """Helper to run nikto."""
        command = ["nikto", "-h", url]
        return run_command(command, "Nikto Scan", output_file, output_format)
    
    def run_wpscan(self, url, output_file, output_format):
        """Helper to run wpscan."""
        c_warn("WPScan can be rate-limited. Using --random-user-agent.")
        command = [
            "wpscan", 
            "--url", url, 
            "--random-user-agent",
            "--disable-tls-checks",
            "--no-update" # We assume user updates manually
        ]
        return run_command(command, "WPScan", output_file, output_format)

    def do_subdomains(self, args):
        """Run Subfinder to discover subdomains."""
        output_file, output_format = self._validate_output_args(args)
        if not args.domain:
            c_error("Subdomain scan requires a domain.")
            return
        command = ["subfinder", "-d", args.domain, "-silent"]
        return run_command(command, "Subdomain Enumeration (Subfinder)", output_file, output_format)

    def do_recon(self, args):
        """Run passive recon (WHOIS + DIG)."""
        output_file, output_format = self._validate_output_args(args)
        if not args.domain:
            c_error("Recon requires a domain.")
            return
        
        full_output = ""
        whois_out = run_command(["whois", args.domain], "WHOIS Lookup", output_file, output_format)
        if whois_out: full_output += whois_out
        
        dig_out = run_command(["dig", args.domain, "ANY", "+short"], "DNS Record (DIG)", output_file, output_format)
        if dig_out: full_output += dig_out
        
        return full_output

    def do_smb(self, args):
        """Run enum4linux-ng for SMB enumeration."""
        output_file, output_format = self._validate_output_args(args)
        if not args.ip:
            c_error("SMB scan requires an IP address.")
            return
        command = ["enum4linux-ng", "-A", args.ip]
        return run_command(command, "SMB Enumeration (enum4linux-ng)", output_file, output_format)

    def do_snmp(self, args):
        """Run snmp-check for SNMP enumeration."""
        output_file, output_format = self._validate_output_args(args)
        if not args.ip:
            c_error("SNMP scan requires an IP address.")
            return
        command = ["snmp-check", args.ip, "-c", "public"]
        return run_command(command, "SNMP Enumeration (snmp-check)", output_file, output_format)

    def do_search(self, args):
        """Run Searchsploit to find exploits."""
        output_file, output_format = self._validate_output_args(args)
        if not args.query:
            c_error("Search requires a query.")
            return
        command = ["searchsploit"] + args.query
        return run_command(command, f"Exploit Search: {' '.join(args.query)}", output_file, output_format)

    def do_full_scan(self, args):
        """Run an automated, non-interactive scan chain."""
        output_file, output_format = self._validate_output_args(args)
        if not args.domain:
            c_error("Full scan requires a domain.")
            return
        
        c_title(f"Starting Full Scan on {args.domain}")

        # 1. Recon
        # Create a dummy args object for do_recon
        recon_args = argparse.Namespace(domain=args.domain, output=args.output, format=args.format)
        self.do_recon(recon_args)

        # 2. Subdomain Enum
        subfinder_output = run_command(
            ["subfinder", "-d", args.domain, "-silent"],
            "Subdomain Enumeration (Subfinder)",
            output_file,
            output_format
        )
        
        if not subfinder_output:
            c_error("Subfinder failed, aborting full scan.")
            return
        
        subdomains = [line.strip() for line in subfinder_output.split('\n') if line.strip()]
        if not subdomains:
            c_warn(f"No subdomains found for {args.domain}. Scanning the main domain only.")
            subdomains = [args.domain]
        else:
            c_success(f"Found {len(subdomains)} subdomains.")

        # 3. Nmap & Web Scan on each subdomain
        for sub in subdomains:
            c_title(f"Scanning Subdomain: {sub}")
            
            # 3a. Nmap Quick Scan
            nmap_output = run_command(
                ["nmap", sub, "-F", "-T4"], # Fast scan
                f"Nmap Quick Scan on {sub}",
                output_file,
                output_format
            )

            if nmap_output is None:
                c_warn(f"Nmap failed on {sub}, skipping web scan.")
                continue

            # 3b. Check for web ports and run web scan
            web_ports = ["80/tcp", "443/tcp", "8080/tcp", "8443/tcp"]
            if any(port in nmap_output for port in web_ports):
                c_info(f"Web port found on {sub}. Running web scan...")
                
                # Determine URL (try https first)
                url = f"https://{sub}"
                try:
                    # Quick check if https is available
                    # We use curl as it's a common dependency
                    subprocess.run(["curl", "-k", "--head", "-s", "-I", "--connect-timeout", "5", url], capture_output=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    url = f"http://{sub}" # Fallback to http
                
                c_info(f"Using URL: {url}")
                
                # Run the non-interactive web scan
                wappalyzer_output = run_command(
                    ["wappalyzer-cli", url],
                    f"Wappalyzer on {url}",
                    output_file,
                    output_format
                )

                if wappalyzer_output:
                    is_wordpress = "wordpress" in wappalyzer_output.lower()
                    if is_wordpress:
                        self.run_wpscan(url, output_file, output_format)
                    else:
                        self.run_nikto(url, output_file, output_format)
            else:
                c_info(f"No common web ports found on {sub}. Skipping web scan.")

        c_success(f"Full scan on {args.domain} is complete.")

    def do_schedule(self, args):
        """Manage scheduled scans via cron."""
        try:
            user_cron = CronTab(user=True)
        except Exception as e:
            c_error(f"Could not access crontab. Error: {e}")
            c_warn("On some systems, you may need to run `crontab -e` manually once.")
            return

        if args.list:
            c_title("Scheduled Auto-Mate Scans")
            jobs = [job for job in user_cron if "Auto-Mate Scheduled Scan" in job.comment]
            if not jobs:
                c_info("No scheduled scans found.")
                return
            for i, job in enumerate(jobs):
                print(f"  {Fore.YELLOW}[{i+1}]{Style.RESET_ALL} {job.command}")
                print(f"    {Fore.CYAN}Schedule: {job.slices}{Style.RESET_ALL}\n")
        
        elif args.remove:
            jobs = [job for job in user_cron if "Auto-Mate Scheduled Scan" in job.comment]
            if not jobs:
                c_info("No scheduled scans found to remove.")
                return
            
            c_title("Remove a Scheduled Scan")
            for i, job in enumerate(jobs):
                print(f"  {Fore.YELLOW}[{i+1}]{Style.RESET_ALL} {job.command} ({job.slices})")
            
            try:
                choice = int(input("Enter the number of the scan to remove (0 to cancel): "))
                if 0 < choice <= len(jobs):
                    user_cron.remove(jobs[choice-1])
                    user_cron.write()
                    c_success("Scheduled scan removed.")
                else:
                    c_info("Cancelled.")
            except ValueError:
                c_error("Invalid input.")

        else:
            # Interactive wizard to add a new job
            c_title("Schedule a New Scan")
            c_info("This will add a new entry to your user's crontab.")
            
            schedule = input("Enter cron schedule (e.g., '0 9 * * 1' for 9am every Monday): ")
            command_to_run = input("Enter command (e.g., 'full-scan example.com'): ")
            
            # Get full path to python and this script
            python_path = sys.executable
            script_path = Path(__file__).resolve()
            
            full_command = f"{python_path} {script_path} {command_to_run}"
            
            # Default log file
            default_log = LOG_FILE
            log_path = input(f"Enter log file path (default: {default_log}): ")
            if not log_path:
                log_path = default_log
            
            # Validate and create log file path
            log_file_path = validate_path(log_path, create_dir=True)
            if not log_file_path:
                c_error("Invalid log file path. Aborting.")
                return
            
            full_command_with_log = f"{full_command} -o {log_file_path} --format text >> {log_file_path} 2>&1"
            
            job = user_cron.new(command=full_command_with_log, comment="Auto-Mate Scheduled Scan")
            
            if not job.setall(schedule):
                c_error("Invalid cron schedule format. Aborting.")
                return
            
            c_success("New scan job created:")
            print(f"  {Fore.CYAN}Schedule: {job.slices}{Style.RESET_ALL}")
            print(f"  {Fore.CYAN}Command: {job.command}{Style.RESET_ALL}")
            
            if get_user_confirmation("Save this job to your crontab?"):
                user_cron.write()
                c_success("Job saved.")
            else:
                c_info("Job discarded.")

# --- Argument Parsing ---
import argparse

class ReplParser:
    """A custom parser to handle REPL-style commands."""
    
    def __init__(self, commands_instance):
        self.parser = self._create_main_parser()
        self.commands = commands_instance
        self.func_map = self._get_func_map()

    def _get_func_map(self):
        """Maps command names to their handler functions."""
        return {
            'sys-info': self.commands.do_sys_info,
            'nmap': self.commands.do_nmap,
            'nikto': self.commands.do_nikto,
            'ffuf': self.commands.do_ffuf,
            'web': self.commands.do_web,
            'subdomains': self.commands.do_subdomains,
            'recon': self.commands.do_recon,
            'smb': self.commands.do_smb,
            'snmp': self.commands.do_snmp,
            'search': self.commands.do_search,
            'full-scan': self.commands.do_full_scan,
            'schedule': self.commands.do_schedule,
            'help': lambda args: self.parser.print_help(),
            'exit': lambda args: sys.exit(0),
            'quit': lambda args: sys.exit(0),
        }

    def _create_main_parser(self):
        parser = argparse.ArgumentParser(
            description=f"{APP_NAME}: All-in-One Security Suite",
            prog="auto-mate",
            add_help=False # We handle help ourselves
        )
        # Global flags
        parser.add_argument("-o", "--output", help="Save output to a file.")
        parser.add_argument("--format", choices=['text', 'html'], help="Output format (default: text).")
        parser.add_argument("--gui", action="store_true", help="Launch the web GUI.")

        subparsers = parser.add_subparsers(dest="command", help="Available commands")

        # --- sys-info ---
        subparsers.add_parser('sys-info', help="Display local system information.")

        # --- nmap ---
        p_nmap = subparsers.add_parser('nmap', help="Run Nmap scan.", add_help=False)
        p_nmap.add_argument('target', help="Target spec (IP, domain, or range).")
        p_nmap.add_argument('-t', '--threads', help="Thread/Timing (-T flag, 1-5 or count)")
        p_nmap.add_argument('nmap_args', nargs=argparse.REMAINDER, help="Additional Nmap arguments (e.g., -A, -p-).")

        # --- nikto ---
        p_nikto = subparsers.add_parser('nikto', help="Run Nikto scan.", add_help=False)
        p_nikto.add_argument('url', help="Target URL (e.g., http://example.com).")
        p_nikto.add_argument('nikto_args', nargs=argparse.REMAINDER, help="Additional Nikto arguments.")

        # --- ffuf ---
        p_ffuf = subparsers.add_parser('ffuf', help="Run FFUF scan.")
        p_ffuf.add_argument('-u', '--url', help="Target URL with 'FUZZ' keyword.")
        p_ffuf.add_argument('-w', '--wordlist', help="Path to wordlist.")
        p_ffuf.add_argument('-e', '--extensions', help="Comma-separated file extensions.")
        p_ffuf.add_argument('-mc', '--match-codes', help="Match status codes (e.g., 200,301).")
        p_ffuf.add_argument('-fc', '--filter-codes', help="Filter status codes (e.g., 404,500).")
        p_ffuf.add_argument('-t', '--threads', help="Number of concurrent threads.")

        # --- web ---
        p_web = subparsers.add_parser('web', help="Run smart web scan (Wappalyzer + WPScan/Nikto).")
        p_web.add_argument('url', help="Target URL (e.g., http://example.com).")

        # --- subdomains ---
        p_sub = subparsers.add_parser('subdomains', help="Find subdomains with Subfinder.")
        p_sub.add_argument('domain', help="Target domain (e.g., example.com).")

        # --- recon ---
        p_recon = subparsers.add_parser('recon', help="Run passive recon (WHOIS + DIG).")
        p_recon.add_argument('domain', help="Target domain (e.g., example.com).")

        # --- smb ---
        p_smb = subparsers.add_parser('smb', help="Enumerate SMB with enum4linux-ng.")
        p_smb.add_argument('ip', help="Target IP address.")

        # --- snmp ---
        p_snmp = subparsers.add_parser('snmp', help="Enumerate SNMP with snmp-check.")
        p_snmp.add_argument('ip', help="Target IP address.")

        # --- search ---
        p_search = subparsers.add_parser('search', help="Search Exploit-DB with Searchsploit.")
        p_search.add_argument('query', nargs='+', help="Search query (e.g., 'WordPress 5.8').")

        # --- full-scan ---
        p_full = subparsers.add_parser('full-scan', help="Run automated full scan (Recon > Subdomains > Nmap > Web).")
        p_full.add_argument('domain', help="Target domain (e.g., example.com).")

        # --- schedule ---
        p_sched = subparsers.add_parser('schedule', help="Manage scheduled scans (cron).")
        p_sched.add_argument('--list', action='store_true', help="List scheduled scans.")
        p_sched.add_argument('--remove', action='store_true', help="Remove a scheduled scan.")

        # --- help, exit, quit ---
        subparsers.add_parser('help', help="Show this help message.")
        subparsers.add_parser('exit', help="Exit the shell.")
        subparsers.add_parser('quit', help="Exit the shell.")

        return parser

    def parse_and_run(self, args_list):
        """Parse a list of args and run the corresponding command."""
        try:
            # Parse known args. This allows global flags like -o
            # to be passed with subcommands.
            args, remaining = self.parser.parse_known_args(args_list)

            # Handle global flags
            if args.output:
                self.commands.output_file = validate_path(args.output, create_dir=True)
            if args.format:
                self.commands.output_format = args.format
            
            # Handle GUI launch
            if args.gui:
                start_gui(self.commands)
                return
            
            # Re-parse to get subcommand-specific args
            if args.command == 'nmap' or args.command == 'nikto':
                # These commands use nargs=REMAINDER, so we need to
                # re-parse with the 'remaining' args included.
                args = self.parser.parse_args(args_list)
            elif args.command == 'search':
                args = self.parser.parse_args(args_list)
            elif args.command is None:
                # No command given (e.g., just 'python nscan.py -o file.txt')
                self.parser.print_help()
                return

            if args.command in self.func_map:
                # Dispatch to the correct function
                self.func_map[args.command](args)
            elif args.command:
                c_error(f"Unknown command: {args.command}")
                self.parser.print_help()
            else:
                # No command given (e.g., only '-o' specified)
                self.parser.print_help()
                
        except SystemExit:
            # argparse.ArgumentParser's default 'help' action raises SystemExit
            pass
        except Exception as e:
            c_error(f"Failed to parse command: {e}")

# --- Web GUI (Flask App) ---
app = Flask(__name__)
cli_commands = None # Will be set on GUI launch

# This is the GUI's HTML, embedded as a string.
GUI_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auto-Mate Web GUI</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #1a1a1a; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: 20px auto; background: #2a2a2a; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); overflow: hidden; }
        .header { background: #333; color: #00e5ff; padding: 20px; }
        .header h1 { margin: 0; font-size: 2em; }
        .form-container { padding: 25px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-weight: 600; color: #b0b0b0; margin-bottom: 8px; }
        .form-group select, .form-group input[type="text"] {
            width: 100%; padding: 12px; background: #3c3c3c; border: 1px solid #555; border-radius: 6px; color: #e0e0e0; font-size: 1em; box-sizing: border-box;
        }
        .form-group input::placeholder { color: #888; }
        .form-group button {
            background-color: #007bff; color: white; padding: 12px 20px; border: none; border-radius: 6px; font-size: 1em; font-weight: 600; cursor: pointer; transition: background-color 0.3s ease;
        }
        .form-group button:hover { background-color: #0056b3; }
        .form-group-inline { display: flex; gap: 10px; }
        .form-group-inline > div { flex: 1; }
        #ffuf-options, #nmap-options, #nikto-options, #web-options, #subdomains-options, #recon-options, #smb-options, #snmp-options, #search-options { display: none; }
        .results { padding: 25px; border-top: 1px solid #444; }
        .results h2 { color: #00e5ff; margin-top: 0; }
        #loading { display: none; text-align: center; padding: 20px; }
        #loading .spinner {
            border: 4px solid #f3f3f3; border-top: 4px solid #007bff; border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        pre { background: #1e1e1e; color: #d0d0d0; padding: 15px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-family: "Courier New", Courier, monospace; }
        .error { color: #ff4d4d; font-weight: bold; }
        .json-result { background-color: #272727; border: 1px solid #444; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>Auto-Mate Web GUI</h1></div>
        <div class="form-container">
            <div class="form-group">
                <label for="tool-select">Select Tool</label>
                <select id="tool-select">
                    <option value="web">Web Scan (Smart)</option>
                    <option value="nmap">Nmap</option>
                    <option value="ffuf">FFUF</option>
                    <option value="nikto">Nikto</option>
                    <option value="subdomains">Subdomains</option>
                    <option value="recon">Recon (WHOIS + DIG)</option>
                    <option value="smb">SMB Enum</option>
                    <option value="snmp">SNMP Enum</option>
                    <option value="search">Exploit Search</option>
                </select>
            </div>

            <!-- Nmap Options -->
            <div id="nmap-options">
                <div class="form-group">
                    <label for="nmap-target">Target(s)</label>
                    <input type="text" id="nmap-target" placeholder="scanme.nmap.org, 192.168.1.0/24">
                </div>
                <div class="form-group-inline">
                    <div class="form-group">
                        <label for="nmap-profile">Scan Profile</label>
                        <select id="nmap-profile">
                            <option value="-F -T4">Quick Scan</option>
                            <option value="-A -T4">Aggressive Scan</option>
                            <option value="-sS -sV -O -T4">Stealth & Version Scan</option>
                            <option value="-p- -T4">Full Port Scan</option>
                            <option value="--script vuln -T4">Vuln Scan</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="nmap-threads">Threads</label>
                        <input type="text" id="nmap-threads" placeholder="Default (e.g., 100)">
                    </div>
                </div>
            </div>

            <!-- FFUF Options -->
            <div id="ffuf-options">
                <div class="form-group">
                    <label for="ffuf-url">URL (must include 'FUZZ')</label>
                    <input type="text" id="ffuf-url" placeholder="http://example.com/FUZZ">
                </div>
                <div class="form-group">
                    <label for="ffuf-wordlist">Wordlist Path</label>
                    <input type="text" id="ffuf-wordlist" placeholder="/usr/share/wordlists/common.txt">
                </div>
                <div class="form-group-inline">
                    <div class="form-group">
                        <label for="ffuf-extensions">Extensions (.php, .txt)</label>
                        <input type="text" id="ffuf-extensions" placeholder=".php,.txt">
                    </div>
                    <div class="form-group">
                        <label for="ffuf-match">Match Codes (200,301)</label>
                        <input type="text" id="ffuf-match" placeholder="200,301,302">
                    </div>
                    <div class="form-group">
                        <label for="ffuf-threads">Threads</label>
                        <input type="text" id="ffuf-threads" placeholder="Default (40)">
                    </div>
                </div>
            </div>

            <!-- Web/Nikto/Subdomains/Recon (Single Target) -->
            <div id="web-options" class="form-group">
                <label for="web-target">Target URL</label>
                <input type="text" id="web-target" placeholder="http://example.com">
            </div>
            <div id="nikto-options" class="form-group">
                <label for="nikto-target">Target URL</label>
                <input type="text" id="nikto-target" placeholder="http://example.com">
            </div>
            <div id="subdomains-options" class="form-group">
                <label for="subdomains-target">Target Domain</label>
                <input type="text" id="subdomains-target" placeholder="example.com">
            </div>
            <div id="recon-options" class="form-group">
                <label for="recon-target">Target Domain</label>
                <input type="text" id="recon-target" placeholder="example.com">
            </div>
            
            <!-- SMB/SNMP (Single IP) -->
            <div id="smb-options" class="form-group">
                <label for="smb-target">Target IP</label>
                <input type="text" id="smb-target" placeholder="192.168.1.10">
            </div>
            <div id="snmp-options" class="form-group">
                <label for="snmp-target">Target IP</label>
                <input type="text" id="snmp-target" placeholder="192.168.1.1">
            </div>

            <!-- Search -->
            <div id="search-options" class="form-group">
                <label for="search-query">Search Query</label>
                <input type="text" id="search-query" placeholder="WordPress 5.8">
            </div>

            <div class="form-group">
                <button id="run-scan">Run Scan</button>
            </div>
        </div>

        <div id="loading"><div class="spinner"></div><p>Running scan...</p></div>
        
        <div class="results" id="results-container" style="display:none;">
            <h2>Results</h2>
            <pre id="results-output"></pre>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const toolSelect = document.getElementById('tool-select');
            const runButton = document.getElementById('run-scan');
            const loading = document.getElementById('loading');
            const resultsContainer = document.getElementById('results-container');
            const resultsOutput = document.getElementById('results-output');

            const allOptions = [
                'nmap-options', 'ffuf-options', 'web-options', 'nikto-options', 
                'subdomains-options', 'recon-options', 'smb-options', 
                'snmp-options', 'search-options'
            ];

            function showOptions(tool) {
                allOptions.forEach(opt => {
                    document.getElementById(opt).style.display = 'none';
                });
                document.getElementById(tool + '-options').style.display = 'block';
            }

            toolSelect.addEventListener('change', () => {
                showOptions(toolSelect.value);
            });
            // Show initial
            showOptions('web');

            runButton.addEventListener('click', async () => {
                const tool = toolSelect.value;
                let payload = { tool: tool };

                // Collect data based on selected tool
                if (tool === 'nmap') {
                    payload.target = document.getElementById('nmap-target').value;
                    payload.profile = document.getElementById('nmap-profile').value;
                    payload.threads = document.getElementById('nmap-threads').value;
                } else if (tool === 'ffuf') {
                    payload.url = document.getElementById('ffuf-url').value;
                    payload.wordlist = document.getElementById('ffuf-wordlist').value;
                    payload.extensions = document.getElementById('ffuf-extensions').value;
                    payload.match_codes = document.getElementById('ffuf-match').value;
                    payload.threads = document.getElementById('ffuf-threads').value;
                } else if (tool === 'web') {
                    payload.target = document.getElementById('web-target').value;
                } else if (tool === 'nikto') {
                    payload.target = document.getElementById('nikto-target').value;
                } else if (tool === 'subdomains') {
                    payload.target = document.getElementById('subdomains-target').value;
                } else if (tool === 'recon') {
                    payload.target = document.getElementById('recon-target').value;
                } else if (tool === 'smb') {
                    payload.target = document.getElementById('smb-target').value;
                } else if (tool === 'snmp') {
                    payload.target = document.getElementById('snmp-target').value;
                } else if (tool === 'search') {
                    payload.target = document.getElementById('search-query').value;
                }

                // Show loading, hide results
                loading.style.display = 'block';
                resultsContainer.style.display = 'none';
                resultsOutput.innerHTML = '';

                try {
                    const response = await fetch('/api/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    const data = await response.json();

                    if (data.error) {
                        resultsOutput.innerHTML = `<span class="error">${data.error}</span>`;
                    } else if (typeof data.result === 'object') {
                        // Pretty print JSON
                        resultsOutput.innerHTML = escapeHTML(JSON.stringify(data.result, null, 2));
                        resultsOutput.classList.add('json-result');
                    } else {
                        // Plain text
                        resultsOutput.innerHTML = escapeHTML(data.result);
                        resultsOutput.classList.remove('json-result');
                    }

                } catch (err) {
                    resultsOutput.innerHTML = `<span class="error">Request failed: ${err.message}</span>`;
                }

                // Hide loading, show results
                loading.style.display = 'none';
                resultsContainer.style.display = 'block';
            });

            function escapeHTML(str) {
                return str.replace(/[&<>"']/g, function(m) {
                    return {
                        '&': '&amp;',
                        '<': '&lt;',
                        '>': '&gt;',
                        '"': '&quot;',
                        "'": '&#39;'
                    }[m];
                });
            }
        });
    </script>
</body>
</html>
"""

@app.route("/")
def gui_home():
    """Serves the main HTML GUI page."""
    return GUI_HTML_TEMPLATE

@app.route("/api/scan", methods=['POST'])
def api_scan():
    """Handles scan requests from the web GUI."""
    data = request.json
    tool = data.get('tool')
    
    # We use a global instance of ToolCommands
    if not cli_commands:
        return jsonify({"error": "Server not initialized."}), 500
    
    # Set output to HTML for all GUI scans
    cli_commands.output_format = 'html'
    
    try:
        # Simulate argparse Namespace object
        args = argparse.Namespace()
        args.output = None # Don't write to file from GUI
        args.format = 'html'

        if tool == 'nmap':
            args.target = data.get('target')
            args.nmap_args = shlex.split(data.get('profile', ''))
            args.threads = data.get('threads')
            # Nmap output is just text
            result = cli_commands.do_nmap(args)
            return jsonify({"result": result})

        elif tool == 'ffuf':
            args.url = data.get('url')
            args.wordlist = data.get('wordlist')
            args.extensions = data.get('extensions')
            args.match_codes = data.get('match_codes')
            args.filter_codes = None # Not in GUI for simplicity
            args.threads = data.get('threads')
            result = cli_commands.do_ffuf(args)
            return jsonify({"result": result})

        elif tool == 'web':
            args.url = data.get('target')
            # This is complex. We need to run this non-interactively
            # and capture JSON, which is different from the CLI flow.
            c_info(f"GUI: Running non-interactive web scan on {args.url}")
            tech = cli_commands._run_wappalyzer_json(args.url)
            vulns = {}
            if "WordPress" in str(tech):
                vulns = cli_commands._run_wpscan_json(args.url)
            else:
                vulns = cli_commands._run_nikto_json(args.url)
            return jsonify({"result": {"technologies": tech, "vulnerabilities": vulns}})

        elif tool == 'nikto':
            args.url = data.get('target')
            args.nikto_args = []
            result = cli_commands.do_nikto(args)
            return jsonify({"result": result})

        elif tool == 'subdomains':
            args.domain = data.get('target')
            result = cli_commands.do_subdomains(args)
            return jsonify({"result": result})

        elif tool == 'recon':
            args.domain = data.get('target')
            result = cli_commands.do_recon(args)
            return jsonify({"result": result})
            
        elif tool == 'smb':
            args.ip = data.get('target')
            result = cli_commands.do_smb(args)
            return jsonify({"result": result})
            
        elif tool == 'snmp':
            args.ip = data.get('target')
            result = cli_commands.do_snmp(args)
            return jsonify({"result": result})

        elif tool == 'search':
            args.query = shlex.split(data.get('target', ''))
            result = cli_commands.do_search(args)
            return jsonify({"result": result})

        else:
            return jsonify({"error": f"Unknown tool: {tool}"}), 400

    except Exception as e:
        c_error(f"GUI scan error: {e}")
        return jsonify({"error": str(e)}), 500

# Helper functions for GUI backend
# These are simplified and need to be implemented
def _run_wappalyzer_json(self, url):
    c_info(f"GUI: Running Wappalyzer on {url}")
    try:
        result = subprocess.run(["wappalyzer-cli", url], capture_output=True, text=True, timeout=60)
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}

def _run_wpscan_json(self, url):
    c_info(f"GUI: Running WPScan on {url}")
    command = ["wpscan", "--url", url, "--random-user-agent", "--disable-tls-checks", "--no-update", "-f", "json"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        return json.loads(result.stdout)
    except Exception as e:
        return {"error": str(e)}

def _run_nikto_json(self, url):
    c_info(f"GUI: Running Nikto on {url}")
    command = ["nikto", "-h", url, "-Format", "json"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        # Try to parse the weird, multi-line JSON
        for line in result.stdout.splitlines():
            try:
                data = json.loads(line)
                if "vulnerabilities" in data:
                    return data # Return the main data object
            except json.JSONDecodeError:
                continue
        return {"error": "Could not parse Nikto JSON", "raw": result.stdout}
    except Exception as e:
        return {"error": str(e)}

# Bind helper functions to the class
ToolCommands._run_wappalyzer_json = _run_wappalyzer_json
ToolCommands._run_wpscan_json = _run_wpscan_json
ToolCommands._run_nikto_json = _run_nikto_json


def start_gui(commands_instance):
    """Starts the Flask web server for the GUI."""
    global cli_commands
    cli_commands = commands_instance
    
    url = f"http://127.0.0.1:{GUI_PORT}"
    c_info(f"Starting Web GUI at {url}")
    
    # Open browser in a new thread
    threading.Timer(1, lambda: webbrowser.open(url)).start()
    
    # Run Flask app
    try:
        # Disable Flask's default logging to keep our CLI clean
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        app.run(host="127.0.0.1", port=GUI_PORT, debug=False)
    except Exception as e:
        c_error(f"Failed to start GUI: {e}")
        c_warn("Another process may be using the port.")


# --- Main Execution ---
def main():
    colorama.init()

    # Create instances
    commands = ToolCommands()
    parser = ReplParser(commands)

    # Check for non-REPL, one-shot command
    if len(sys.argv) > 1:
        parser.parse_and_run(sys.argv[1:])
        sys.exit(0)

    # Start REPL mode
    print_banner()
    c_info(f"Welcome to the {APP_NAME} interactive shell.")
    c_info("Type 'help' for commands, 'exit' or 'quit' to leave.")
    
    # Check all tools on startup
    commands.check_all_tools()
    
    while True:
        try:
            prompt = f"{Style.BRIGHT}{Fore.GREEN}auto-mate > {Style.RESET_ALL}"
            line = input(prompt).strip()
            
            if not line:
                continue
            
            # Split the line using shlex for proper quote handling
            try:
                args = shlex.split(line)
            except ValueError as e:
                c_error(f"Syntax error: {e}")
                continue

            parser.parse_and_run(args)

        except KeyboardInterrupt:
            print("\nExiting. (Type 'exit' or 'quit')")
        except EOFError:
            print("\nExiting.")
            sys.exit(0)
        except Exception as e:
            c_error(f"An unexpected error occurred: {e}")
            # Optionally, log the full traceback to the log file
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                import traceback
                f.write(f"\n--- UNEXPECTED ERROR: {datetime.now()} ---\n")
                traceback.print_exc(file=f)
            c_warn(f"Full error details logged to {LOG_File}")


if __name__ == "__main__":
    main()

# --- End of Script ---