import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Base URL of the Caddy server
BASE_URL = "http://localhost:8082"

# Test cases
test_cases = [
    {
        "name": "Normal GET request",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "params": {"param1": "value1"},
        "expected_status": 200,
    },
    {
        "name": "Normal POST request",
        "method": "POST",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com", "Content-Type": "application/json"},
        "data": '{"key": "value"}',
        "expected_status": 200,
    },
    {
        "name": "Large request size (blocked)",
        "method": "POST",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "data": "a" * 3000,  # Exceeds normal_request_size_range
        "expected_status": 403,
    },
    {
        "name": "Too many headers (blocked)",
        "method": "GET",
        "url": BASE_URL,
        "headers": {f"Header-{i}": "value" for i in range(30)},  # Exceeds normal_header_count_range
        "expected_status": 403,
    },
    {
        "name": "Unusual HTTP method (blocked)",
        "method": "PUT",  # Not in normal_http_methods
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "expected_status": 403,
    },
    {
        "name": "Unusual User-Agent (blocked)",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"User-Agent": "BadBot", "Referer": "https://example.com"},
        "expected_status": 403,
    },
    {
        "name": "Unusual Referrer (blocked)",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://malicious.com"},
        "expected_status": 403,
    },
    {
        "name": "Too many query parameters (blocked)",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "params": {f"param{i}": "value" for i in range(10)},  # Exceeds normal_query_param_count_range
        "expected_status": 403,
    },
    {
        "name": "Too many path segments (blocked)",
        "method": "GET",
        "url": f"{BASE_URL}/segment1/segment2/segment3/segment4/segment5/segment6",  # Exceeds normal_path_segment_count_range
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "expected_status": 403,
    },
    {
        "name": "Empty request body",
        "method": "POST",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com", "Content-Type": "application/json"},
        "data": "",  # Empty body
        "expected_status": 200,  # or 403 if empty body is considered suspicious
    },
    {
        "name": "Malformed JSON body",
        "method": "POST",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com", "Content-Type": "application/json"},
        "data": '{"key": "value"',  # Malformed JSON
        "expected_status": 403,
    },
    {
        "name": "Unusual Content-Type",
        "method": "POST",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com", "Content-Type": "application/xml"},
        "data": "<key>value</key>",  # XML instead of JSON
        "expected_status": 403,
    },
    {
        "name": "Missing User-Agent",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"Referer": "https://example.com"},  # No User-Agent
        "expected_status": 403,
    },
    {
        "name": "Missing Referrer",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome"},  # No Referer
        "expected_status": 200,  # or 403 if missing Referer is considered suspicious
    },
    {
        "name": "Unusual Path",
        "method": "GET",
        "url": f"{BASE_URL}/admin",  # Unusual path
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "expected_status": 403,
    },
    {
        "name": "Unusual Query Parameter",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "params": {"debug": "true"},  # Unusual query parameter
        "expected_status": 403,
    },
    {
        "name": "High Request Rate",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "params": {"param1": "value1"},
        "expected_status": 403,  # If rate limiting is enabled
    },
    {
        "name": "Mixed Case Headers",
        "method": "GET",
        "url": BASE_URL,
        "headers": {"user-agent": "Chrome", "referer": "https://example.com"},  # Mixed case headers
        "expected_status": 200,  # or 403 if mixed case headers are considered suspicious
    },
    # New test cases for /api path
    {
        "name": "Normal GET request to /api",
        "method": "GET",
        "url": f"{BASE_URL}/api",
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "params": {"param1": "value1"},
        "expected_status": 200,
    },
    {
        "name": "Large request size to /api (blocked)",
        "method": "POST",
        "url": f"{BASE_URL}/api",
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "data": "a" * 3000,  # Exceeds normal_request_size_range
        "expected_status": 403,
    },
    {
        "name": "Unusual HTTP method to /api (blocked)",
        "method": "PUT",  # Not in normal_http_methods
        "url": f"{BASE_URL}/api",
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "expected_status": 403,
    },
    {
        "name": "Unusual User-Agent to /api (blocked)",
        "method": "GET",
        "url": f"{BASE_URL}/api",
        "headers": {"User-Agent": "BadBot", "Referer": "https://example.com"},
        "expected_status": 403,
    },
    {
        "name": "Unusual Referrer to /api (blocked)",
        "method": "GET",
        "url": f"{BASE_URL}/api",
        "headers": {"User-Agent": "Chrome", "Referer": "https://malicious.com"},
        "expected_status": 403,
    },
    {
        "name": "Too many query parameters to /api (blocked)",
        "method": "GET",
        "url": f"{BASE_URL}/api",
        "headers": {"User-Agent": "Chrome", "Referer": "https://example.com"},
        "params": {f"param{i}": "value" for i in range(10)},  # Exceeds normal_query_param_count_range
        "expected_status": 403,
    },
]

# Run test cases
results = []
for test in test_cases:
    print(f"{Fore.CYAN}Running test: {test['name']}{Style.RESET_ALL}")
    try:
        response = requests.request(
            method=test["method"],
            url=test["url"],
            headers=test.get("headers", {}),
            params=test.get("params", {}),
            data=test.get("data", None),
        )
        status_code = response.status_code
        is_suspicious = "X-Suspicious-Traffic" in response.headers

        # Check if the result matches the expected status
        if status_code == test["expected_status"]:
            result = f"{Fore.GREEN}PASS{Style.RESET_ALL}"
        else:
            result = f"{Fore.RED}FAIL{Style.RESET_ALL}"

        # Append result to the results list
        results.append((test["name"], result, status_code, is_suspicious))

        # Print detailed output
        print(f"Status Code: {status_code}")
        print(f"Response: {response.text}")
        if is_suspicious:
            print(f"{Fore.YELLOW}Traffic marked as suspicious!{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        result = f"{Fore.RED}FAIL{Style.RESET_ALL}"
        results.append((test["name"], result, "Request failed", False))
        print(f"{Fore.RED}Request failed: {e}{Style.RESET_ALL}")
    print("-" * 40)

# Print summary
print(f"{Fore.CYAN}\nTest Summary:{Style.RESET_ALL}")
for name, result, status_code, is_suspicious in results:
    print(f"{name}: {result} (Status: {status_code}, Suspicious: {is_suspicious})")

# Count passes and fails
pass_count = sum(1 for _, result, _, _ in results if "PASS" in result)
fail_count = len(results) - pass_count

# Print final result
if fail_count == 0:
    print(f"\n{Fore.GREEN}All tests passed!{Style.RESET_ALL}")
else:
    print(f"\n{Fore.RED}{fail_count} tests failed.{Style.RESET_ALL}")
