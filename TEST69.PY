import subprocess

# Function to install a Python library if not already installed
def install_library(library_name):
    try:
        __import__(library_name)
    except ImportError:
        print(f"{library_name} not found. Installing...")
        subprocess.run(['pip', 'install', library_name])

# Install necessary libraries
libraries = ['subprocess', 'urllib', 'socket', 'requests', 'bs4', 'whois', 'dns']
for lib in libraries:
    install_library(lib)

import subprocess
from urllib.parse import urlparse
import socket
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver

# ASCII art for "VIGIL.X"
vigil_art = """
  ___      ___ ___  ________  ___  ___              ___    ___ 
 |\  \    /  /|\  \|\   ____\|\  \|\  \            |\  \  /  /|
 \ \  \  /  / | \  \ \  \___|\ \  \ \  \           \ \  \/  / /
  \ \  \/  / / \ \  \ \  \  __\ \  \ \  \           \ \    / / 
   \ \    / /   \ \  \ \  \|\  \ \  \ \  \____  ___  /     \/  
    \ \__/ /     \ \__\ \_______\ \__\ \_______\__\/  /\   \  
     \|__|/       \|__|\|_______|\|__|\|_______\|__/__/ /\ __\ 
                                                   |__|/ \|__| 
"""

print(vigil_art)


# Function to fetch WHOIS information
def get_whois_information(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error fetching WHOIS information: {e}"


# Function to fetch subdomains
def get_subdomains(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return f"No DNS record found for {domain}"
    except Exception as e:
        return f"Error fetching subdomains: {e}"


# Function to fetch security headers
def get_security_headers(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else "N/A"

        headers = {
            "Title": title,
            "X-Frame-Options": response.headers.get("X-Frame-Options", "N/A"),
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "N/A"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "N/A"),
            "Content-Security-Policy": response.headers.get("Content-Security-Policy", "N/A"),
        }
        return headers
    except Exception as e:
        return f"Error fetching security headers: {e}"


# Function to check for authentication bypass vulnerability
def check_authentication_bypass_vulnerability(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    payload = "admin' OR '1'='1' --"
    response = requests.post(url, data={"username": payload, "password": ""})

    if "Welcome, admin!" in response.text:
        print("Authentication Bypass vulnerability found. Access granted without valid credentials.")
    else:
        print("No Authentication Bypass vulnerability detected.")


# Function to check for file inclusion vulnerability
def check_file_inclusion_vulnerability(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    payload = "../../../../etc/passwd"
    response = requests.get(f"{url}?file={payload}")

    if "root:" in response.text:
        print("File Inclusion vulnerability found. Remote code execution possible.")
    else:
        print("No File Inclusion vulnerability detected.")


# Function to check for security misconfigurations
def check_security_misconfigurations(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    response = requests.get(url)

    if "Index of /" in response.text:
        print("Open directory found. Consider securing it.")
    else:
        print("No open directory detected.")

    sensitive_keywords = ["password", "secret", "api_key"]
    for keyword in sensitive_keywords:
        if keyword in response.text:
            print(f"Sensitive information ({keyword}) exposed. Consider securing it.")


# Function to check for XSS vulnerability
def check_xss_vulnerability(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    xss_payload = '<script>alert("XSS Vulnerability");</script>'
    response_with_xss = requests.get(f"{url}?input={xss_payload}")

    if xss_payload in response_with_xss.text:
        print("Possible XSS vulnerability found.")
    else:
        print("No XSS vulnerability detected.")


# Function to check for SQL injection vulnerability
def check_sql_injection(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    payload = "1' OR '1'='1'; --"
    response = requests.get(f"{url}?id={payload}")

    if "error" in response.text.lower():
        print("Possible SQL injection vulnerability found.")
    else:
        print("No SQL injection vulnerability detected.")


# Function to retrieve CSRF token from HTML content
def get_csrf_token(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    csrf_input = soup.find('input', {'name': 'csrf_token'})
    if csrf_input:
        csrf_token = csrf_input.get('value', '')
        return csrf_token
    else:
        return None


# Function to check for CSRF vulnerability
def check_csrf_vulnerability(url):
    if not urlparse(url).scheme:
        url = 'http://' + url

    response = requests.get(url)
    csrf_token = get_csrf_token(response.text)

    payload = {
        'username': 'attacker',
        'password': 'malicious_password',
        'csrf_token': csrf_token
    }

    malicious_request = requests.post(url, data=payload)
    if malicious_request.status_code == 200:
        print(f"Potential CSRF vulnerability found at: {url}")
    else:
        print("CSRF protection is in place.")


# Function to conduct an active vulnerability scan
def active_scan(url):
    print("Starting Active Scan for:", url)
    print("-" * 40)

    print("\n1. Authentication Bypass Scan:")
    check_authentication_bypass_vulnerability(url)

    print("\n2. File Inclusion Scan:")
    check_file_inclusion_vulnerability(url)

    print("\n3. Security Misconfigurations Scan:")
    check_security_misconfigurations(url)

    print("\n4. Cross-Site Scripting (XSS) Scan:")
    check_xss_vulnerability(url)

    print("\n5. SQL Injection Scan:")
    check_sql_injection(url)

    print("\n6. CSRF (Cross-Site Request Forgery) Scan:")
    check_csrf_vulnerability(url)


# Function to obtain the IP address from a domain
def get_ip_from_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address

    except socket.error as e:
        print(f"Error during DNS resolution: {e}")
        return None


# Function to conduct a port scan using Nmap
def port_scan(target_ip):
    try:
        nmap_command = f'nmap {target_ip}'

        result = subprocess.check_output(nmap_command, shell=True, universal_newlines=True)

        print(result)

    except subprocess.CalledProcessError as e:
        print(f"Error during port scan: {e}")


# Function to fetch domain information using WHOIS
def get_domain_info(domain_name):
    try:
        domain_info = whois.whois(domain_name)
        return domain_info
    except whois.parser.PywhoisError as e:
        print(f"Error fetching WHOIS information: {e}")
        return None


# Function to print domain information
def print_domain_info(domain_info):
    if domain_info:
        print("\nDomain:", domain_info.domain)
        print("Registrar:", domain_info.registrar)
        print("Registered On:", domain_info.creation_date)
        print("Expires On:", domain_info.expiration_date)
        print("Updated On:", domain_info.updated_date)
        print("Status:", domain_info.status)
        print("Name Servers:", domain_info.name_servers)

        print("\nRegistrant Contact")
        print("Organization:", domain_info.registrant_name)
        print("Country:", domain_info.registrant_country)
        print("Email:", domain_info.registrant_email)

        print("\nAdministrative Contact")
        print("Email:", domain_info.admin_email)

        print("\nTechnical Contact")
        print("Email:", domain_info.tech_email)

        print("\nRaw Whois Data:")
        print(domain_info.text)
    else:
        print("No domain information found.")


# Function to conduct directory enumeration using dirsearch
def conduct_directory_enumeration(url, extensions=".php,.html,.js,.txt,.css", quiet_mode=True, simple_output=True):
    try:
        # Construct the command based on user input
        command = ["dirsearch", "-u", url]

        # Add options if user provided input
        if extensions:
            command.extend(["-e", extensions])
        if not quiet_mode:
            command.append("-q")
        if not simple_output:
            command.append("-f")

        # Run the dirsearch command
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Error during directory enumeration: {e}")


# Main function to execute all functionalities
def main():
    while True:
        print("\nOptions:")
        print("1. OWASP Scan")
        print("2. Domain Scan")
        print("3. Open Port Scan")
        print("4. Files and Directory Scan")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == "1":
            owasp_choice = input("Select OWASP Scan type (1. Active Scan, 2. Passive Scan): ")
            if owasp_choice == "1":
                # Active Scan
                target_url = input("Enter the target website URL: ")
                active_scan(target_url)
            elif owasp_choice == "2":
                # Passive Scan
                target_url = input("Enter the target website URL: ")
                whois_info = get_whois_information(target_url)
                subdomains = get_subdomains(target_url)
                security_headers = get_security_headers("http://" + target_url)
                print("\nWHOIS Information:")
                print(whois_info)
                print("\nSubdomains:")
                print(subdomains)
                print("\nSecurity Headers:")
                for header, value in security_headers.items():
                    print(f"{header}: {value}")
            else:
                print("Invalid choice. Please enter 1 or 2.")

        elif choice == "2":
            # Domain Scan
            target_url = input("Enter the target website URL: ")
            domain_info = get_domain_info(target_url)
            print_domain_info(domain_info)

        elif choice == "3":
            # Open Port Scan
            target_url = input("Enter the target website URL: ")
            target_ip = get_ip_from_domain(target_url)
            if target_ip:
                port_scan(target_ip)
            else:
                print("Unable to obtain the IP address. Check the website name and try again.")

        elif choice == "4":
            # Files and Directory Scan
            target_url = input("Enter the target website URL: ")
            conduct_directory_enumeration(target_url)

        elif choice == "5":
            print("Exiting the program.")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 5.")


if __name__ == "__main__":
    main()

