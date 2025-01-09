#!/bin/bash

# Server URL
SERVER_URL="http://localhost:8080"

# WAF Thresholds
MAX_REQUEST_SIZE=1500
MIN_REQUEST_SIZE=10
MAX_HEADER_COUNT=10
MIN_HEADER_COUNT=2
MAX_HEADER_VALUE_LENGTH=400

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to perform a test and return the status code
run_test() {
  local test_name="$1"
  local url="$2"
  local method="${3:-GET}"
  local data="${4:-}"
  local headers="${5:-}"
  local expected_status="$6"
  local description="${7:-}"

  printf "${CYAN}--- Test: %s ---${NC}\n" "$test_name"
  if [ -n "$description" ]; then
    echo "  $description"
  fi

  local curl_command="curl -s -w '%{http_code}\\n'"

  if [ -n "$headers" ]; then
    IFS=$'\n' read -r -d '' -a header_lines <<< "$headers"
    for header in "${header_lines[@]}"; do
      curl_command+=" -H '$header'"
    done
  fi

  if [ "$method" == "POST" ] || [ "$method" == "PUT" ]; then
    curl_command+=" -X $method -d '$data'"
  fi

  local output=$(eval "$curl_command '$url'")
  local actual_status=$(echo "$output" | grep -oE '[0-9]{3}')

  local status_color=$GREEN
  if [[ ! "$actual_status" =~ ^$expected_status$ ]]; then
    status_color=$RED
  fi
  printf "  Status Code: %s%s%s\n" "$status_color" "$actual_status" "$NC"

  if [[ ! "$actual_status" =~ ^$expected_status$ ]]; then
    printf "    ${RED}Expected: %s, Actual: %s${NC}\n" "$expected_status" "$actual_status"
    echo "    Command: $curl_command '$url'"
  fi

  echo "$actual_status"
}

generate_random_string() {
  openssl rand -base64 "$(( ($1 * 3 / 4) + 3 ))" | head -c "$1"
}

# Initialize counters
total_tests=0
unexpected_behavior=0

# --- Baseline Tests ---
total_tests=$((total_tests + 1))
baseline_status=$(run_test "Baseline - Normal GET" "$SERVER_URL/normal" GET "" "" "2.." "Should allow basic GET requests.")
if [[ ! "$baseline_status" =~ ^2[0-9]{2}$ ]]; then
  printf "${YELLOW}WARN: Baseline test failed (non-2xx). WAF might be blocking basic requests.${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

# --- Request Size Tests ---
total_tests=$((total_tests + 1))
exceed_max_size=$((MAX_REQUEST_SIZE + 100))
large_request_status=$(run_test "Request Size - Exceeding Max" "$SERVER_URL/large-request" POST "$(generate_random_string $exceed_max_size)" "" "4.." "Should block requests larger than the maximum size ($MAX_REQUEST_SIZE bytes).")
if [[ ! "$large_request_status" =~ ^4[0-9]{2}$ ]]; then
  printf "${RED}FAIL: Request Size - Exceeding Max did NOT trigger WAF (non-4xx).${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
below_min_size=$((MIN_REQUEST_SIZE - 5))
small_request_status=$(run_test "Request Size - Below Min" "$SERVER_URL/small-request" POST "$(generate_random_string $below_min_size)" "" "2.." "Should allow requests smaller than the minimum size ($MIN_REQUEST_SIZE bytes).")
if [[ ! "$small_request_status" =~ ^2[0-9]{2}$ ]]; then
  printf "${RED}FAIL: Request Size - Below Min triggered WAF (non-2xx).${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
at_max_size="$MAX_REQUEST_SIZE"
at_max_request_status=$(run_test "Request Size - At Max Threshold" "$SERVER_URL/normal" POST "$(generate_random_string $at_max_size)" "" "2.." "Should allow requests at the maximum size threshold ($MAX_REQUEST_SIZE bytes).")
if [[ ! "$at_max_request_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Request Size - At Max triggered WAF (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
just_below_max_size=$((MAX_REQUEST_SIZE - 1))
just_below_max_status=$(run_test "Request Size - Just Below Max" "$SERVER_URL/normal" POST "$(generate_random_string $just_below_max_size)" "" "2.." "Should allow requests just below the maximum size threshold.")
if [[ ! "$just_below_max_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Request Size - Just Below Max unexpectedly blocked (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
at_min_size="$MIN_REQUEST_SIZE"
at_min_request_status=$(run_test "Request Size - At Min Threshold" "$SERVER_URL/normal" POST "$(generate_random_string $at_min_size)" "" "2.." "Should allow requests at the minimum size threshold ($MIN_REQUEST_SIZE bytes).")
if [[ ! "$at_min_request_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Request Size - At Min triggered WAF (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
just_above_min_size=$((MIN_REQUEST_SIZE + 1))
just_above_min_status=$(run_test "Request Size - Just Above Min" "$SERVER_URL/normal" POST "$(generate_random_string $just_above_min_size)" "" "2.." "Should allow requests just above the minimum size threshold.")
if [[ ! "$just_above_min_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Request Size - Just Above Min unexpectedly blocked (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

# --- Header Count Tests ---
total_tests=$((total_tests + 1))
exceed_max_headers=$((MAX_HEADER_COUNT + 5))
declare -a many_headers_array
for i in $(seq 1 $exceed_max_headers); do
  many_headers_array+=("X-Custom-Header-$i: value$i")
done
many_headers_string=$(IFS=$'\n' ; echo "${many_headers_array[*]}")
many_headers_status=$(run_test "Header Count - Exceeding Max" "$SERVER_URL/many-headers" GET "" "$many_headers_string" "4.." "Should block requests with more than the maximum number of headers ($MAX_HEADER_COUNT).")
if [[ ! "$many_headers_status" =~ ^4[0-9]{2}$ ]]; then
  printf "${RED}FAIL: Header Count - Exceeding Max did NOT trigger WAF (non-4xx).${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
below_min_headers=$((MIN_HEADER_COUNT - 1))
declare -a few_headers_array
for i in $(seq 1 $below_min_headers); do
  few_headers_array+=("X-Custom-Header-$i: value$i")
done
few_headers_string=$(IFS=$'\n' ; echo "${few_headers_array[*]}")
few_headers_status=$(run_test "Header Count - Below Min" "$SERVER_URL/few-headers" GET "" "$few_headers_string" "2.." "Should allow requests with fewer than the minimum number of headers ($MIN_HEADER_COUNT).")
if [[ ! "$few_headers_status" =~ ^2[0-9]{2}$ ]]; then
  printf "${RED}FAIL: Header Count - Below Min triggered WAF (non-2xx).${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
at_max_headers="$MAX_HEADER_COUNT"
declare -a at_max_headers_array
for i in $(seq 1 $at_max_headers); do
  at_max_headers_array+=("X-Custom-Header-$i: value$i")
done
at_max_headers_string=$(IFS=$'\n' ; echo "${at_max_headers_array[*]}")
at_max_headers_status=$(run_test "Header Count - At Max Threshold" "$SERVER_URL/normal" GET "" "$at_max_headers_string" "2.." "Should allow requests with the maximum number of headers ($MAX_HEADER_COUNT).")
if [[ ! "$at_max_headers_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Header Count - At Max triggered WAF (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
just_below_max_headers=$((MAX_HEADER_COUNT - 1))
declare -a just_below_max_headers_array
for i in $(seq 1 $just_below_max_headers); do
  just_below_max_headers_array+=("X-Custom-Header-$i: value$i")
done
just_below_max_headers_string=$(IFS=$'\n' ; echo "${just_below_max_headers_array[*]}")
just_below_max_headers_status=$(run_test "Header Count - Just Below Max" "$SERVER_URL/normal" GET "" "$just_below_max_headers_string" "2.." "Should allow requests just below the maximum number of headers.")
if [[ ! "$just_below_max_headers_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Header Count - Just Below Max unexpectedly blocked (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
at_min_headers="$MIN_HEADER_COUNT"
declare -a at_min_headers_array
for i in $(seq 1 $at_min_headers); do
  at_min_headers_array+=("X-Custom-Header-$i: value$i")
done
at_min_headers_string=$(IFS=$'\n' ; echo "${at_min_headers_array[*]}")
at_min_headers_status=$(run_test "Header Count - At Min Threshold" "$SERVER_URL/normal" GET "" "$at_min_headers_string" "2.." "Should allow requests with the minimum number of headers ($MIN_HEADER_COUNT).")
if [[ ! "$at_min_headers_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Header Count - At Min triggered WAF (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

total_tests=$((total_tests + 1))
just_above_min_headers=$((MIN_HEADER_COUNT + 1))
declare -a just_above_min_headers_array
for i in $(seq 1 $just_above_min_headers); do
  just_above_min_headers_array+=("X-Custom-Header-$i: value$i")
done
just_above_min_headers_string=$(IFS=$'\n' ; echo "${just_above_min_headers_array[*]}")
just_above_min_headers_status=$(run_test "Header Count - Just Above Min" "$SERVER_URL/normal" GET "" "$just_above_min_headers_string" "2.." "Should allow requests just above the minimum number of headers.")
if [[ ! "$just_above_min_headers_status" =~ ^2[0-9]{2}$ ]]; then
    printf "${YELLOW}WARN: Header Count - Just Above Min unexpectedly blocked (non-2xx), check threshold configuration.${NC}\n"
    unexpected_behavior=$((unexpected_behavior + 1))
fi

# --- Combined Tests ---
total_tests=$((total_tests + 1))
large_and_many_headers_count=$((MAX_HEADER_COUNT - 2))
declare -a large_and_many_headers_array
for i in $(seq 1 $large_and_many_headers_count); do
  large_and_many_headers_array+=("X-Custom-Header-$i: value$i")
done
large_and_many_headers_string=$(IFS=$'\n' ; echo "${large_and_many_headers_array[*]}")
large_and_many_size=$((MAX_REQUEST_SIZE - 200))
large_and_many_status=$(run_test "Combined - Large Request and Many Headers" "$SERVER_URL/large-and-many" POST "$(generate_random_string $large_and_many_size)" "$large_and_many_headers_string" "2.." "Should allow requests near the limits of both size and header count.")
if [[ ! "$large_and_many_status" =~ ^2[0-9]{2}$ ]]; then
  printf "${YELLOW}WARN: Combined - Large Request and Many Headers triggered WAF (non-2xx), check threshold interaction.${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

# --- Potentially Malicious Path Test ---
total_tests=$((total_tests + 1))
malicious_path_status=$(run_test "Potentially Malicious Path" "$SERVER_URL/../../etc/passwd" GET "" "" "4.." "Should block requests with potentially malicious paths.")
if [[ ! "$malicious_path_status" =~ ^4[0-9]{2}$ ]]; then
  printf "${RED}FAIL: Potentially Malicious Path did NOT trigger WAF (non-4xx).${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

# --- Non-Existent Path Test ---
total_tests=$((total_tests + 1))
nonexistent_path_status=$(run_test "Non-Existent Path" "$SERVER_URL/this-path-does-not-exist" GET "" "" "404" "Should return a 404 status for non-existent paths.")
if [[ "$nonexistent_path_status" != "404" ]]; then
  printf "${YELLOW}WARN: Non-Existent Path did not return 404, check server configuration.${NC}\n"
fi

# --- Different HTTP Methods ---
total_tests=$((total_tests + 1))
put_test_status=$(run_test "HTTP Method - PUT" "$SERVER_URL/data" PUT "some data" "" "403" "Should return 403 for PUT requests on this resource.")
if [[ "$put_test_status" != "403" ]]; then
    printf "${YELLOW}WARN: HTTP Method - PUT did not return 403, check server/WAF configuration.${NC}\n"
fi

total_tests=$((total_tests + 1))
delete_test_status=$(run_test "HTTP Method - DELETE" "$SERVER_URL/data/123" DELETE "" "" "403" "Should return 403 for DELETE requests on this resource.")
if [[ "$delete_test_status" != "403" ]]; then
    printf "${YELLOW}WARN: HTTP Method - DELETE did not return 403, check server/WAF configuration.${NC}\n"
fi

# --- Headers with unusual characters ---
total_tests=$((total_tests + 1))
unusual_header_status=$(run_test "Headers - Unusual Characters" "$SERVER_URL/normal" GET "" "X-Weird-Header: !@#$%^&*()" "4.." "Should block headers with unusual characters.")
if [[ ! "$unusual_header_status" =~ ^4[0-9]{2}$ ]]; then
  printf "${RED}FAIL: Headers - Unusual Characters did NOT trigger WAF (non-4xx).${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

# --- Long Header Value ---
total_tests=$((total_tests + 1))
exceed_header_length=$((MAX_HEADER_VALUE_LENGTH + 100))
long_header_value=$(generate_random_string $exceed_header_length)
long_header_status=$(run_test "Headers - Long Value" "$SERVER_URL/normal" GET "" "X-Long-Header: $long_header_value" "4.." "Should block headers with values exceeding the maximum length ($MAX_HEADER_VALUE_LENGTH).")
if [[ ! "$long_header_status" =~ ^4[0-9]{2}$ ]]; then
  printf "${RED}FAIL: Headers - Long Value did NOT trigger WAF (non-4xx).${NC}\n"
  unexpected_behavior=$((unexpected_behavior + 1))
fi

printf "${YELLOW}--- Test Summary ---${NC}\n"
echo "Total Tests Run: $total_tests"
printf "Tests with Unexpected WAF Behavior: ${RED}%d${NC}\n" "$unexpected_behavior"
if [ "$total_tests" -gt 0 ]; then
  error_percentage=$(echo "scale=2; $unexpected_behavior * 100 / $total_tests" | bc | awk '{printf "%.2f", $1}')
  printf "Percentage of Unexpected WAF Behavior: ${RED}%s%%%s${NC}\n" "$error_percentage"
fi
echo

# Removing the detailed test results section
# printf "${YELLOW}--- Detailed Test Results ---${NC}\n"
# printf "Baseline - Normal GET: Status Code: %s\n" "$baseline_status"
# printf "Request Size - Exceeding Max: Status Code: %s\n" "$large_request_status"
# printf "Request Size - Below Min: Status Code: %s\n" "$small_request_status"
# printf "Request Size - At Max Threshold: Status Code: %s\n" "$at_max_request_status"
# printf "Request Size - Just Below Max: Status Code: %s\n" "$just_below_max_status"
# printf "Request Size - At Min Threshold: Status Code: %s\n" "$at_min_request_status"
# printf "Request Size - Just Above Min: Status Code: %s\n" "$just_above_min_status"
# printf "Header Count - Exceeding Max: Status Code: %s\n" "$many_headers_status"
# printf "Header Count - Below Min: Status Code: %s\n" "$few_headers_status"
# printf "Header Count - At Max Threshold: Status Code: %s\n" "$at_max_headers_status"
# printf "Header Count - Just Below Max: Status Code: %s\n" "$just_below_max_headers_status"
# printf "Header Count - At Min Threshold: Status Code: %s\n" "$at_min_headers_status"
# printf "Header Count - Just Above Min: Status Code: %s\n" "$just_above_min_headers_status"
# printf "Combined - Large Request and Many Headers: Status Code: %s\n" "$large_and_many_status"
# printf "Potentially Malicious Path: Status Code: %s\n" "$malicious_path_status"
# printf "Non-Existent Path: Status Code: %s\n" "$nonexistent_path_status"
# printf "HTTP Method - PUT: Status Code: %s\n" "$put_test_status"
# printf "HTTP Method - DELETE: Status Code: %s\n" "$delete_test_status"
# printf "Headers - Unusual Characters: Status Code: %s\n" "$unusual_header_status"
# printf "Headers - Long Value: Status Code: %s\n" "$long_header_status"

printf "\n${CYAN}Tests completed. Review the summary and detailed results, especially ${RED}FAIL${NC} and ${YELLOW}WARN${NC} messages.${NC}\n"