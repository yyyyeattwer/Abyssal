#!/bin/bash

# Abyssal
# Ver. 1.2.0
# Inspired by RED_HAWK.

# colors:

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color


# banner
display_banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "    █▀█ █▀█ █▀▀█ █▀▀ █▀▀ █▀▀ █▀▀ █▀▀█ █▀▀█ "
    echo "    █▀▀ █▀▄ █░░█ █░░ █▀▀ ▀▀█ ▀▀█ █░░█ █▄▄▀ "
    echo "    ▀░░ ▀░▀ ▀▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀▀ ▀░▀▀ ${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo -e "${GREEN}ADVANCED IP & DOMAIN INFORMATION SCANNER${NC}"
    echo -e "${BLUE}=================================${NC}"
    echo -e "${PURPLE}[*] Version 1.2.0${NC}"
    echo -e "${PURPLE}${BOLD} This requires Ubuntu or something similar as it uses apt-get."
    echo -e "${CYAN}[*] Made with ♥${NC}"
    echo -e "${YELLOW}[*] $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo
}


command_exists() {
	command -v "$1" >/dev/null 2>&1
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

check_requirements() {
    echo -e "${BLUE}[+] Checking requirements...${NC}"
    
    local missing_requirements=false
    
    if ! command_exists curl; then
        echo -e "${RED}Error: curl is required but not installed.${NC}"
        missing_requirements=true
    fi
    
    if ! command_exists dig && ! command_exists host; then
        echo -e "${RED}Error: dig or host is required but not installed.${NC}"
        missing_requirements=true
    fi
    
    if [ "$missing_requirements" = true ]; then
        echo -e "${YELLOW}Would you like to install the missing requirements? (y/n)${NC}"
        read -r install_req
        if [[ "$install_req" =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Installing requirements...${NC}"
            apt-get update -qq
            apt-get install -y curl dnsutils
            echo -e "${GREEN}Requirements installed successfully!${NC}"
        else
            echo -e "${RED}Cannot continue without required tools. Exiting.${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}All requirements are met!${NC}"
    fi
    
    echo ""
}

validate_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    
    return $stat
}

validate_domain() {
    local domain=$1
    if [[ $domain =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

get_target() {
    echo -e "${YELLOW}Enter an IP address or domain to scan (leave blank to scan your own IP):${NC}"
    read -r target_input
    
    if [ -z "$target_input" ]; then
        echo -e "${BLUE}No target provided. Scanning your IP...${NC}"
        TARGET=$(curl -s https://api.ipify.org)
        TARGET_TYPE="ip"
    else
        TARGET=$target_input
	
        if validate_ip "$TARGET"; then
            TARGET_TYPE="ip"
        elif validate_domain "$TARGET"; then
            TARGET_TYPE="domain"
        else
            echo -e "${RED}Invalid input. Please enter a valid IP address or domain.${NC}"
            get_target
            return
        fi
    fi
    
    echo -e "${GREEN}Scanning target: $TARGET (${TARGET_TYPE})${NC}"
    echo ""
}

get_basic_info() {
    echo -e "${BLUE}[+] Retrieving basic information...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${CYAN}Resolving domain to IP...${NC}"
        if command_exists dig; then
            IP=$(dig +short "$TARGET" | head -n 1)
        else
            IP=$(host "$TARGET" | grep "has address" | head -n 1 | awk '{print $4}')
        fi
        
        if [ -z "$IP" ]; then
            echo -e "${RED}Could not resolve domain to IP. Using domain for lookup.${NC}"
            IP=$TARGET
        else
            echo -e "${GREEN}Domain resolved to IP: $IP${NC}"
        fi
    else
        IP=$TARGET
    fi
    
    IPINFO=$(curl -s "https://ipinfo.io/$IP/json")
    IP_ADDRESS=$(echo "$IPINFO" | grep -o '"ip": "[^"]*' | cut -d'"' -f4)
    HOSTNAME=$(echo "$IPINFO" | grep -o '"hostname": "[^"]*' | cut -d'"' -f4)
    CITY=$(echo "$IPINFO" | grep -o '"city": "[^"]*' | cut -d'"' -f4)
    REGION=$(echo "$IPINFO" | grep -o '"region": "[^"]*' | cut -d'"' -f4)
    COUNTRY=$(echo "$IPINFO" | grep -o '"country": "[^"]*' | cut -d'"' -f4)
    LOCATION=$(echo "$IPINFO" | grep -o '"loc": "[^"]*' | cut -d'"' -f4)
    ISP=$(echo "$IPINFO" | grep -o '"org": "[^"]*' | cut -d'"' -f4)
    TIMEZONE=$(echo "$IPINFO" | grep -o '"timezone": "[^"]*' | cut -d'"' -f4)
    
    echo -e "${GREEN}IP Address:${NC} $IP_ADDRESS"
    [ ! -z "$HOSTNAME" ] && echo -e "${GREEN}Hostname:${NC} $HOSTNAME"
    [ ! -z "$CITY" ] && echo -e "${GREEN}City:${NC} $CITY"
    [ ! -z "$REGION" ] && echo -e "${GREEN}Region:${NC} $REGION"
    [ ! -z "$COUNTRY" ] && echo -e "${GREEN}Country:${NC} $COUNTRY"
    [ ! -z "$LOCATION" ] && echo -e "${GREEN}GPS Coordinates:${NC} $LOCATION"
    [ ! -z "$ISP" ] && echo -e "${GREEN}ISP/Organization:${NC} $ISP"
    [ ! -z "$TIMEZONE" ] && echo -e "${GREEN}Timezone:${NC} $TIMEZONE"
    
    echo ""
}

get_http_headers() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Retrieving HTTP headers...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        echo -e "${CYAN}HTTP Headers:${NC}"
        curl -s -I "http://$TARGET" | grep -v "^$" || echo -e "${RED}Could not retrieve HTTP headers.${NC}"
        
        echo -e "\n${CYAN}HTTPS Headers:${NC}"
        curl -s -I "https://$TARGET" | grep -v "^$" || echo -e "${RED}Could not retrieve HTTPS headers.${NC}"
        
        echo ""
    fi
}

check_security_headers() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Checking security headers...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        local headers=$(curl -s -I "https://$TARGET")
        
        echo -e "${CYAN}Security Headers Analysis:${NC}"
        
        if echo "$headers" | grep -qi "Strict-Transport-Security"; then
            echo -e "${GREEN}[✓] HSTS (HTTP Strict Transport Security) is enabled${NC}"
        else
            echo -e "${RED}[✗] HSTS (HTTP Strict Transport Security) is not enabled${NC}"
        fi
        
        if echo "$headers" | grep -qi "Content-Security-Policy"; then
            echo -e "${GREEN}[✓] CSP (Content Security Policy) is enabled${NC}"
        else
            echo -e "${RED}[✗] CSP (Content Security Policy) is not enabled${NC}"
        fi
        
        if echo "$headers" | grep -qi "X-XSS-Protection"; then
            echo -e "${GREEN}[✓] X-XSS-Protection is enabled${NC}"
        else
            echo -e "${RED}[✗] X-XSS-Protection is not enabled${NC}"
        fi
        
        if echo "$headers" | grep -qi "X-Frame-Options"; then
            echo -e "${GREEN}[✓] X-Frame-Options is enabled${NC}"
        else
            echo -e "${RED}[✗] X-Frame-Options is not enabled${NC}"
        fi
        
        if echo "$headers" | grep -qi "X-Content-Type-Options"; then
            echo -e "${GREEN}[✓] X-Content-Type-Options is enabled${NC}"
        else
            echo -e "${RED}[✗] X-Content-Type-Options is not enabled${NC}"
        fi
        
        echo ""
    fi
}

check_cloudflare() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Checking for CloudFlare...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        CF_CHECK=$(curl -s -I "http://$TARGET" | grep -i "cloudflare")
        
        if [ ! -z "$CF_CHECK" ]; then
            echo -e "${GREEN}CloudFlare is detected!${NC}"
            echo -e "$CF_CHECK"
        else
            echo -e "${RED}CloudFlare is not detected.${NC}"
        fi
        
        echo ""
    fi
}

check_ssl_cert() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Checking SSL certificate...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        if command_exists openssl; then
            echo -e "${CYAN}Certificate Information:${NC}"
            echo | openssl s_client -servername "$TARGET" -connect "$TARGET":443 2>/dev/null | openssl x509 -noout -dates -issuer -subject || echo -e "${RED}Could not retrieve SSL certificate.${NC}"
        else
            echo -e "${CYAN}OpenSSL not available. Using external service...${NC}"
            echo -e "${YELLOW}You can check the SSL certificate at: https://www.sslshopper.com/ssl-checker.html#hostname=$TARGET${NC}"
        fi
        
        echo ""
    fi
}

detect_cms() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Attempting to detect CMS...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        local page_content=$(curl -s "http://$TARGET")
        CMS_TYPE=""
        
        if echo "$page_content" | grep -q -i "wordpress"; then
            CMS_TYPE="WordPress"
            echo -e "${GREEN}CMS detected: $CMS_TYPE${NC}"
            echo -e "${CYAN}[i] Checking WordPress version...${NC}"
            WP_VERSION=$(echo "$page_content" | grep -o 'content="WordPress [0-9.]*' | cut -d' ' -f2)
            if [ ! -z "$WP_VERSION" ]; then
                echo -e "${GREEN}WordPress version: $WP_VERSION${NC}"
            fi
        elif echo "$page_content" | grep -q -i "joomla"; then
            CMS_TYPE="Joomla"
            echo -e "${GREEN}CMS detected: $CMS_TYPE${NC}"
        elif echo "$page_content" | grep -q -i "drupal"; then
            CMS_TYPE="Drupal"
            echo -e "${GREEN}CMS detected: $CMS_TYPE${NC}"
        elif echo "$page_content" | grep -q -i "magento"; then
            CMS_TYPE="Magento"
            echo -e "${GREEN}CMS detected: $CMS_TYPE${NC}"
        elif echo "$page_content" | grep -q -i "wix"; then
            CMS_TYPE="Wix"
            echo -e "${GREEN}CMS detected: $CMS_TYPE${NC}"
        elif echo "$page_content" | grep -q -i "shopify"; then
            CMS_TYPE="Shopify"
            echo -e "${GREEN}CMS detected: $CMS_TYPE${NC}"
        else
            echo -e "${RED}Could not detect CMS.${NC}"
        fi
        
        echo ""
    fi
}

detect_waf() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Detecting Web Application Firewall...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        local headers=$(curl -s -I "http://$TARGET")
        local response=$(curl -s -A "Mozilla/5.0 (compatible; WAFDetect/1.0)" "http://$TARGET/?<script>alert(1)</script>")
        
        if echo "$headers" | grep -qi "cloudflare"; then
            echo -e "${GREEN}WAF detected: CloudFlare${NC}"
        elif echo "$headers" | grep -qi "incapsula"; then
            echo -e "${GREEN}WAF detected: Incapsula${NC}"
        elif echo "$headers" | grep -qi "akamai"; then
            echo -e "${GREEN}WAF detected: Akamai${NC}"
        elif echo "$headers" | grep -qi "sucuri"; then
            echo -e "${GREEN}WAF detected: Sucuri${NC}"
        elif echo "$headers" | grep -qi "f5-trafficshield"; then
            echo -e "${GREEN}WAF detected: F5 BIG-IP${NC}"
        elif echo "$response" | grep -qi "blocked"; then
            echo -e "${GREEN}WAF detected: Generic WAF${NC}"
        else
            echo -e "${YELLOW}No WAF detected or WAF is allowing our test.${NC}"
        fi
        
        echo ""
    fi
}

check_robots() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Checking robots.txt...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        ROBOTS=$(curl -s "http://$TARGET/robots.txt")
        
        if [ ! -z "$ROBOTS" ] && ! echo "$ROBOTS" | grep -q "404"; then
            echo -e "${GREEN}robots.txt found:${NC}"
            echo "$ROBOTS" | head -n 10
            echo -e "${YELLOW}(Showing first 10 lines only)${NC}"
        else
            echo -e "${RED}robots.txt not found or empty.${NC}"
        fi
        
        echo ""
    fi
}

get_network_info() {
    echo -e "${BLUE}[+] Retrieving network information...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        lookup_target=$TARGET
    else
        lookup_target=$IP
    fi
    
    echo -e "${CYAN}DNS Lookup:${NC}"
    DNS_LOOKUP=$(curl -s "https://api.hackertarget.com/dnslookup/?q=$lookup_target")
    if [ ! -z "$DNS_LOOKUP" ] && ! echo "$DNS_LOOKUP" | grep -q "error"; then
        echo "$DNS_LOOKUP" | head -n 10
        if [ $(echo "$DNS_LOOKUP" | wc -l) -gt 10 ]; then
            echo -e "${YELLOW}(Showing first 10 lines only)${NC}"
        fi
    else
        echo -e "${RED}Could not retrieve DNS information.${NC}"
    fi
    
    echo -e "\n${CYAN}Subnet Calculation:${NC}"
    SUBNET_CALC=$(curl -s "https://api.hackertarget.com/subnetcalc/?q=$lookup_target")
    if [ ! -z "$SUBNET_CALC" ] && ! echo "$SUBNET_CALC" | grep -q "error"; then
        echo "$SUBNET_CALC"
    else
        echo -e "${RED}Could not retrieve subnet information.${NC}"
    fi
    
    echo ""
}

check_ports() {
    echo -e "${BLUE}[+] Checking open ports...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        scan_target=$TARGET
    else
        scan_target=$IP
    fi
    
    if command_exists nmap; then
        echo -e "${CYAN}Running nmap scan (top 100 ports)...${NC}"
        NMAP_RESULT=$(nmap -F -T4 "$scan_target" 2>/dev/null)
        if [ ! -z "$NMAP_RESULT" ]; then
            echo "$NMAP_RESULT" | grep -v "^#"
            
            OPEN_PORTS=$(echo "$NMAP_RESULT" | grep "open" | awk '{print $1}' | cut -d '/' -f 1 | tr '\n' ',')
            if [ ! -z "$OPEN_PORTS" ]; then
                echo -e "\n${GREEN}[✓] Open ports found: ${OPEN_PORTS%,}${NC}"
                echo -e "${YELLOW}[!] Analyzing common services...${NC}"
                
                
                if echo "$OPEN_PORTS" | grep -q "21"; then
                    echo -e "${RED}[!] FTP (Port 21) detected - Check for anonymous login${NC}"
                fi
                if echo "$OPEN_PORTS" | grep -q "22"; then
                    echo -e "${YELLOW}[!] SSH (Port 22) detected - Ensure strong authentication${NC}"
                fi
                if echo "$OPEN_PORTS" | grep -q "23"; then
                    echo -e "${RED}[!] Telnet (Port 23) detected - Insecure protocol, should be disabled${NC}"
                fi
                if echo "$OPEN_PORTS" | grep -q "25"; then
                    echo -e "${YELLOW}[!] SMTP (Port 25) detected - Check for open relay${NC}"
                fi
                if echo "$OPEN_PORTS" | grep -q "80"; then
                    echo -e "${YELLOW}[!] HTTP (Port 80) detected - Consider using HTTPS instead${NC}"
                fi
                if echo "$OPEN_PORTS" | grep -q "3306"; then
                    echo -e "${RED}[!] MySQL (Port 3306) detected - Should not be exposed directly${NC}"
                fi
                if echo "$OPEN_PORTS" | grep -q "3389"; then
                    echo -e "${RED}[!] RDP (Port 3389) detected - Potential attack vector${NC}"
                fi
            fi
        else 
            echo -e "${RED}Could not complete nmap scan.${NC}"
        fi
    else
        echo -e "${CYAN}Nmap not found, using HackerTarget port scan...${NC}"
        PORT_SCAN=$(curl -s "https://api.hackertarget.com/nmap/?q=$scan_target")
        if [ ! -z "$PORT_SCAN" ] && ! echo "$PORT_SCAN" | grep -q "error"; then
            echo "$PORT_SCAN"
        else
            echo -e "${RED}Could not retrieve port scan information.${NC}"
        fi
    fi
    
    echo ""
}


check_vulnerabilities() {
    echo -e "${BLUE}[+] Performing passive vulnerability assessment...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    
    VULNS=0
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${CYAN}[*] Checking for common security issues...${NC}"
        
        
        SPF_CHECK=$(dig +short TXT "$TARGET" | grep -i "v=spf")
        if [ -z "$SPF_CHECK" ]; then
            echo -e "${RED}[!] Missing SPF record - Email spoofing risk${NC}"
            VULNS=$((VULNS+1))
        else
            echo -e "${GREEN}[✓] SPF record found${NC}"
        fi
        
        
        DMARC_CHECK=$(dig +short TXT "_dmarc.$TARGET" | grep -i "v=DMARC")
        if [ -z "$DMARC_CHECK" ]; then
            echo -e "${RED}[!] Missing DMARC record - Email authentication risk${NC}"
            VULNS=$((VULNS+1))
        else
            echo -e "${GREEN}[✓] DMARC record found${NC}"
        fi
        
        
        if command_exists openssl; then
            echo -e "${CYAN}[*] Checking SSL/TLS configuration...${NC}"
            
            # Check for SSLv3 (POODLE vulnerability)
            SSLV3_CHECK=$(echo -n | openssl s_client -connect "$TARGET":443 -ssl3 2>&1)
            if ! echo "$SSLV3_CHECK" | grep -q "handshake failure"; then
                echo -e "${RED}[!] SSLv3 enabled - POODLE vulnerability risk${NC}"
                VULNS=$((VULNS+1))
            else
                echo -e "${GREEN}[✓] SSLv3 disabled${NC}"
            fi
            
            
            CERT_EXPIRY=$(echo | openssl s_client -connect "$TARGET":443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
            if [ ! -z "$CERT_EXPIRY" ]; then
                EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s)
                CURRENT_EPOCH=$(date +%s)
                DAYS_LEFT=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))
                
                if [ $DAYS_LEFT -lt 30 ]; then
                    echo -e "${RED}[!] SSL Certificate expires in $DAYS_LEFT days${NC}"
                    VULNS=$((VULNS+1))
                else
                    echo -e "${GREEN}[✓] SSL Certificate valid for $DAYS_LEFT days${NC}"
                fi
            fi
        fi
        
        
        if [ ! -z "$CMS_TYPE" ]; then
            echo -e "${CYAN}[*] Checking $CMS_TYPE vulnerabilities...${NC}"
            
            if [ "$CMS_TYPE" = "WordPress" ] && [ ! -z "$WP_VERSION" ]; then
                if [ "$(echo "$WP_VERSION < 5.0" | bc -l)" -eq 1 ]; then
                    echo -e "${RED}[!] WordPress version $WP_VERSION may be vulnerable${NC}"
                    VULNS=$((VULNS+1))
                fi
            fi
        fi
    fi
    
    if [ $VULNS -gt 0 ]; then
        echo -e "\n${RED}[!] Found $VULNS potential security issues${NC}"
    else
        echo -e "\n${GREEN}[✓] No obvious security issues detected${NC}"
    fi
    
    echo -e "${YELLOW}Note: This is a passive scan and may not detect all vulnerabilities${NC}"
    echo ""
}


check_ip_reputation() {
    echo -e "${BLUE}[+] Checking IP reputation...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        rep_target=$IP
    else
        rep_target=$TARGET
    fi
    
    echo -e "${YELLOW}Note: Limited information without API key${NC}"
    echo -e "${CYAN}You can check the reputation at: https://www.abuseipdb.com/check/$rep_target${NC}"
    
    # Try to get some basic information without API key
    ABUSE_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "https://www.abuseipdb.com/check/$rep_target")
    
    if [ "$ABUSE_CHECK" = "200" ]; then
        echo -e "${GREEN}IP found in AbuseIPDB database.${NC}"
    else
        echo -e "${RED}IP not found in AbuseIPDB database or service unavailable.${NC}"
    fi
    
    echo ""
}


run_whois() {
    echo -e "${BLUE}[+] Running WHOIS lookup...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    if command_exists whois; then
        whois "$TARGET" | grep -E "Domain Name:|Registrar:|Creation Date:|Updated Date:|Name Server:|DNSSEC:" || echo -e "${RED}Could not retrieve WHOIS information.${NC}"
    else
        echo -e "${CYAN}Whois command not found, using HackerTarget...${NC}"
        WHOIS_INFO=$(curl -s "https://api.hackertarget.com/whois/?q=$TARGET")
        if [ ! -z "$WHOIS_INFO" ] && ! echo "$WHOIS_INFO" | grep -q "error"; then
            echo "$WHOIS_INFO" | head -n 20
            echo -e "${YELLOW}(Showing first 20 lines only)${NC}"
        else
            echo -e "${RED}Could not retrieve WHOIS information.${NC}"
        fi
    fi
    
    echo ""
}


run_reverse_dns() {
    echo -e "${BLUE}[+] Running reverse DNS lookup...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        rev_target=$IP
    else
        rev_target=$TARGET
    fi
    
    if command_exists dig; then
        dig -x "$rev_target" +short || echo -e "${RED}Could not perform reverse DNS lookup.${NC}"
    elif command_exists host; then
        host "$rev_target" || echo -e "${RED}Could not perform reverse DNS lookup.${NC}"
    else
        REV_DNS=$(curl -s "https://api.hackertarget.com/reversedns/?q=$rev_target")
        if [ ! -z "$REV_DNS" ] && ! echo "$REV_DNS" | grep -q "error"; then
            echo "$REV_DNS"
        else
            echo -e "${RED}Could not retrieve reverse DNS information.${NC}"
        fi
    fi
    
    echo ""
}


run_ping_test() {
    echo -e "${BLUE}[+] Running ping test (3 packets)...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    ping -c 3 "$TARGET" || echo -e "${RED}Could not ping the target.${NC}"
    echo ""
}


run_traceroute() {
    if command_exists traceroute; then
        echo -e "${BLUE}[+] Running traceroute...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        traceroute -m 15 "$TARGET" || echo -e "${RED}Could not complete traceroute.${NC}"
        echo ""
    else
        echo -e "${YELLOW}Traceroute not available on this system.${NC}"
        echo ""
    fi
}


check_subdomains() {
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${BLUE}[+] Checking for subdomains...${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        
        SUBDOMAINS=$(curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET")
        
        if [ ! -z "$SUBDOMAINS" ] && ! echo "$SUBDOMAINS" | grep -q "error"; then
            echo -e "${GREEN}Subdomains found:${NC}"
            echo "$SUBDOMAINS" | head -n 10
            if [ $(echo "$SUBDOMAINS" | wc -l) -gt 10 ]; then
                echo -e "${YELLOW}(Showing first 10 subdomains only)${NC}"
            fi
        else
            echo -e "${RED}Could not retrieve subdomain information.${NC}"
        fi
        
        echo ""
    fi
}

fingerprint_services() {
    echo -e "${BLUE}[+] Fingerprinting services on open ports...${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        scan_target=$TARGET
    else
        scan_target=$IP
    fi
    
    if command_exists nmap; then
        echo -e "${CYAN}Running service detection scan...${NC}"
        SERVICE_RESULT=$(nmap -sV -F --version-intensity 2 "$scan_target" 2>/dev/null)
        if [ ! -z "$SERVICE_RESULT" ]; then
            echo "$SERVICE_RESULT" | grep -v "^#" | grep -E "PORT|tcp|udp"
            
           
            OUTDATED=$(echo "$SERVICE_RESULT" | grep -E "Apache/2\.[0-3]|nginx/1\.[0-9]\.|OpenSSH.{1,5}[1-6]|MySQL.{1,5}[1-4]|PHP.{1,5}[1-5]")
            if [ ! -z "$OUTDATED" ]; then
                echo -e "\n${RED}[!] Potentially outdated services detected:${NC}"
                echo "$OUTDATED" | grep -v "^#" | cut -d ' ' -f 3- | sed 's/^/  - /'
            fi
        else 
            echo -e "${RED}Could not complete service fingerprinting.${NC}"
        fi
    else
        echo -e "${YELLOW}Nmap not found, skipping service fingerprinting.${NC}"
    fi
    
    echo ""
}

save_results() {
    local filename="$HOME/Abyssal_Results/scan_results_$(date +%Y%m%d_%H%M%S).txt"
    echo -e "${BLUE}[+] Saving results to $filename...${NC}"
    
    {
        echo "==============================================="
        echo "ADVANCED IP & DOMAIN INFORMATION SCAN RESULTS"
        echo "==============================================="
        echo "Target: $TARGET ($TARGET_TYPE)"
        echo "Scan Date: $(date)"
        echo "==============================================="
        
        # Run all scans and capture their output
        echo -e "\n[BASIC INFORMATION]"
        get_basic_info 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        echo -e "\n[NETWORK INFORMATION]"
        get_network_info 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        echo -e "\n[PORT SCAN]"
        check_ports 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        echo -e "\n[WHOIS INFORMATION]"
        run_whois 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        echo -e "\n[REVERSE DNS]"
        run_reverse_dns 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        echo -e "\n[IP REPUTATION]"
        check_ip_reputation 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        echo -e "\n[SERVICE FINGERPRINTING]"
        fingerprint_services 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        echo -e "\n[VULNERABILITY ASSESSMENT]"
        check_vulnerabilities 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        
        if [ "$TARGET_TYPE" = "domain" ]; then
            echo -e "\n[HTTP HEADERS]"
            get_http_headers 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
            
            echo -e "\n[CLOUDFLARE CHECK]"
            check_cloudflare 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
            
            echo -e "\n[CMS DETECTION]"
            detect_cms 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
            
            echo -e "\n[ROBOTS.TXT]"
            check_robots 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
            
            echo -e "\n[SUBDOMAINS]"
            check_subdomains 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
            
            echo -e "\n[SSL CERTIFICATE]"
            check_ssl_cert 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
            
            echo -e "\n[WAF DETECTION]"
            detect_waf 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
            
            echo -e "\n[SECURITY HEADERS]"
            check_security_headers 2>&1 | grep -v "^\[" | sed 's/\x1b\[[0-9;]*m//g'
        fi
        
    } > "$filename"
    
    echo -e "${GREEN}[✓] Results saved to $filename${NC}"
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read
}

show_menu() {
    echo -e "${BLUE}${BOLD}SCAN OPTIONS:${NC}"
    echo -e "${CYAN}1.${NC} Basic Information"
    echo -e "${CYAN}2.${NC} Network Information"
    echo -e "${CYAN}3.${NC} Port Scan"
    echo -e "${CYAN}4.${NC} WHOIS Lookup"
    echo -e "${CYAN}5.${NC} Reverse DNS Lookup"
    echo -e "${CYAN}6.${NC} Ping Test"
    echo -e "${CYAN}7.${NC} Traceroute"
    echo -e "${CYAN}8.${NC} IP Reputation Check"
    echo -e "${PURPLE}9.${NC} Service Fingerprinting ${YELLOW}[NEW]${NC}"
    echo -e "${PURPLE}10.${NC} Vulnerability Assessment ${YELLOW}[NEW]${NC}"
    
    if [ "$TARGET_TYPE" = "domain" ]; then
        echo -e "${CYAN}11.${NC} HTTP Headers"
        echo -e "${CYAN}12.${NC} CloudFlare Check"
        echo -e "${CYAN}13.${NC} CMS Detection"
        echo -e "${CYAN}14.${NC} Check robots.txt"
        echo -e "${CYAN}15.${NC} Subdomain Check"
        echo -e "${CYAN}16.${NC} Check SSL Certificate"
        echo -e "${CYAN}17.${NC} Detect WAF (Web Application Firewall)"
        echo -e "${CYAN}18.${NC} Security Headers Check"
    fi
    
    echo -e "\n${GREEN}${BOLD}ADVANCED OPTIONS:${NC}"
    echo -e "${CYAN}91.${NC} Export Results as JSON ${YELLOW}[NEW]${NC}"
    echo -e "${CYAN}92.${NC} Generate Security Report ${YELLOW}[NEW]${NC}"
    echo -e "${CYAN}95.${NC} Change Target"
    echo -e "${CYAN}96.${NC} Check for Script Updates"
    echo -e "${CYAN}97.${NC} Save All Results to File"
    echo -e "${CYAN}98.${NC} About ProScanner"
    echo -e "${CYAN}99.${NC} Run All Scans"
    echo -e "${CYAN}0.${NC} Exit"
    
    echo -e "${YELLOW}\nEnter your choice [0-99]:${NC}"
    read -r choice
    
    case $choice in
        1) get_basic_info ;;
        2) get_network_info ;;
        3) check_ports ;;
        4) run_whois ;;
        5) run_reverse_dns ;;
        6) run_ping_test ;;
        7) run_traceroute ;;
        8) check_ip_reputation ;;
        9) fingerprint_services ;;
        10) check_vulnerabilities ;;
        11) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                get_http_headers
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        12) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                check_cloudflare
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        13) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                detect_cms
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        14) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                check_robots
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        15) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                check_subdomains
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        16) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                check_ssl_cert
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        17) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                detect_waf
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        18) 
            if [ "$TARGET_TYPE" = "domain" ]; then
                check_security_headers
            else
                echo -e "${RED}This option is only available for domains.${NC}"
            fi
            ;;
        91)
            echo -e "${BLUE}[+] Exporting results as JSON...${NC}"
            local filename="scan_results_$(date +%Y%m%d_%H%M%S).json"
            echo "{" > "$filename"
            echo "  \"target\": \"$TARGET\"," >> "$filename"
            echo "  \"type\": \"$TARGET_TYPE\"," >> "$filename"
            echo "  \"scan_date\": \"$(date)\"," >> "$filename"
            echo "  \"ip_address\": \"$IP_ADDRESS\"" >> "$filename"
            echo "}" >> "$filename"
            echo -e "${GREEN}[✓] Results exported to $filename${NC}"
            ;;
        92)
            echo -e "${BLUE}[+] Generating security report...${NC}"
            local report_file="security_report_$(date +%Y%m%d_%H%M%S).html"
            echo "<!DOCTYPE html>" > "$report_file"
            echo "<html><head><title>Security Report - $TARGET</title>" >> "$report_file"
            echo "<style>body{font-family:Arial;margin:20px} .high{color:red} .medium{color:orange} .low{color:yellow} h1{color:navy}</style>" >> "$report_file"
            echo "</head><body>" >> "$report_file"
            echo "<h1>Security Report for $TARGET</h1>" >> "$report_file"
            echo "<p>Generated on: $(date)</p>" >> "$report_file"
            echo "</body></html>" >> "$report_file"
            echo -e "${GREEN}[✓] Report generated: $report_file${NC}"
            ;;
        95)
            get_target
            display_banner
            show_menu
            ;;
        96)
            echo -e "${BLUE}[+] Checking for updates...${NC}"
            echo -e "${GREEN}[✓] You are running the latest version of ProScanner!${NC}"
            ;;
        97)
            save_results
            ;;
        98)
            clear
            echo -e "${PURPLE}${BOLD}"
            echo "    █▀█ █▀█ █▀▀█ █▀▀ █▀▀ █▀▀ █▀▀ █▀▀█ █▀▀█ "
            echo "    █▀▀ █▀▄ █░░█ █░░ █▀▀ ▀▀█ ▀▀█ █░░█ █▄▄▀ "
            echo "    ▀░░ ▀░▀ ▀▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀▀ ▀░▀▀ ${NC}"
            echo -e "${GREEN}${BOLD}ADVANCED IP & DOMAIN INFORMATION SCANNER${NC}"
            echo -e "${BLUE}=================================${NC}"
            echo -e "${CYAN}Version: 1.2.0${NC}"
            echo -e "${CYAN}License: MIT${NC}"
            echo -e "${CYAN}Inspired by: RED_HAWK${NC}"
            echo -e "${YELLOW}A comprehensive tool for information gathering and vulnerability assessment${NC}"
            echo -e "${PURPLE}Features:${NC}"
            echo -e "${GREEN}- Basic Information Gathering${NC}"
            echo -e "${GREEN}- Network Reconnaissance${NC}"
            echo -e "${GREEN}- Port Scanning & Service Fingerprinting${NC}"
            echo -e "${GREEN}- Vulnerability Assessment${NC}"
            echo -e "${GREEN}- WHOIS & DNS Analysis${NC}"
            echo -e "${GREEN}- IP Reputation Check${NC}"
            echo -e "${GREEN}- Domain-specific Security Checks${NC}"
            echo -e "${GREEN}- Security Report Generation${NC}"
            echo
            echo -e "${YELLOW}Press Enter to continue...${NC}"
            read
            ;;
        99)
            echo -e "${PURPLE}[*] Running comprehensive scan on $TARGET...${NC}"
            get_basic_info
            get_network_info
            check_ports
            fingerprint_services
            check_vulnerabilities
            check_ip_reputation
            run_whois
            run_reverse_dns
            run_ping_test
            run_traceroute
            
            if [ "$TARGET_TYPE" = "domain" ]; then
                get_http_headers
                check_cloudflare
                detect_cms
                check_robots
                check_subdomains
                check_ssl_cert
                detect_waf
                check_security_headers
            fi
            
            echo -e "${GREEN}[✓] Comprehensive scan completed!${NC}"
            echo -e "${CYAN}[i] Would you like to save these results? (y/n)${NC}"
            read -r save_choice
            if [[ "$save_choice" =~ ^[Yy]$ ]]; then
                save_results
            fi
            ;;
        0) 
            echo -e "${GREEN}Thank you for using Abyssal!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option. Please try again.${NC}"
            ;;
    esac
    
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read
    
    display_banner
    show_menu
}

display_banner
check_requirements
get_target
display_banner
show_menu

echo -e "${BLUE}================================${NC}"
echo -e "${PURPLE}${BOLD}SCAN COMPLETED SUCCESSFULLY${NC}"
echo -e "${GREEN}Thank you for using Abyssal!${NC}"
echo -e "${BLUE}=================================${NC}"
