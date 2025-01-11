import requests
import argparse
from termcolor import colored
from collections import Counter

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Enhanced Caddy WAF Testing Script with Metrics")
    parser.add_argument(
        "--host", required=True, help="The host URL of the WAF (e.g., http://localhost:8080)"
    )
    parser.add_argument(
        "--num-tests", type=int, required=True, help="Total number of test cases to generate"
    )
    return parser.parse_args()

# Generate test cases with flexible distribution
def generate_test_cases(num_tests):
    test_cases = []
    tests_per_level = num_tests // 10
    extra_tests = num_tests % 10  # Leftover tests to distribute

    for level in range(1, 11):  # Severity levels 1 to 10
        # Distribute leftover tests evenly across levels
        additional_test = 1 if level <= extra_tests else 0
        for _ in range(tests_per_level + additional_test):
            method, payload, headers, data, expected_status, is_malicious = generate_payload(level)
            test_cases.append({
                "level": level,
                "method": method,
                "payload": payload,
                "headers": headers,
                "data": data,
                "expected_status": expected_status,
                "is_malicious": is_malicious,
            })
    return test_cases

# Generate payload based on severity level
def generate_payload(level):
    # Legit requests for levels 1-2
    if level <= 2:
        return "GET", "/home", {}, None, 200, False
    # Suspicious headers and payloads for levels 3-4
    elif level <= 4:
        headers = {"X-Suspicious": "<script>alert('test')</script>", "User-Agent": "badbot/1.0"}
        return "GET", "/search", headers, None, 403, True
    # SQL Injection for levels 5-6
    elif level <= 6:
        payloads = ["/search?q=' OR 1=1 --", "/search?q=test' UNION SELECT NULL, NULL --"]
        return "POST", payloads[level % 2], {}, None, 403, True
    # XSS and file inclusion for levels 7-8
    elif level <= 8:
        payloads = ["/home?<script>alert(1)</script>", "/download?file=../../etc/passwd"]
        headers = {"Referer": "http://malicious-site.com"}
        return "POST", payloads[level % 2], headers, {"data": "test"}, 403, True
    # Time-based SQLi and tampered cookies for levels 9-10
    else:
        payloads = ["/search?q=test' AND SLEEP(5) --", "/home"]
        headers = {"Cookie": "session=invalid_token", "X-Forwarded-For": "1.2.3.4"}
        return "PUT", payloads[level % 2], headers, None, 403, True

# Execute test cases
def execute_tests(host, test_cases):
    results = []
    for test in test_cases:
        try:
            response = requests.request(
                method=test["method"],
                url=f"{host}{test['payload']}",
                headers=test["headers"],
                data=test["data"],
                timeout=5,
            )
            actual_status = response.status_code
            is_correct = (actual_status == test["expected_status"])
            results.append({
                "level": test["level"],
                "method": test["method"],
                "payload": test["payload"],
                "expected_status": test["expected_status"],
                "actual_status": actual_status,
                "is_correct": is_correct,
                "is_malicious": test["is_malicious"],
            })
        except Exception as e:
            results.append({
                "level": test["level"],
                "method": test["method"],
                "payload": test["payload"],
                "expected_status": test["expected_status"],
                "actual_status": f"Error: {str(e)}",
                "is_correct": False,
                "is_malicious": test["is_malicious"],
            })
    return results

# Display results with colors and metrics
def display_results(results):
    confusion_matrix = Counter({"TP": 0, "FP": 0, "TN": 0, "FN": 0})

    for result in results:
        level = result["level"]
        payload = result["payload"]
        expected = result["expected_status"]
        actual = result["actual_status"]
        is_correct = result["is_correct"]
        is_malicious = result["is_malicious"]

        # Update confusion matrix
        if is_malicious and is_correct:
            confusion_matrix["TP"] += 1
        elif not is_malicious and not is_correct:
            confusion_matrix["FP"] += 1
        elif not is_malicious and is_correct:
            confusion_matrix["TN"] += 1
        elif is_malicious and not is_correct:
            confusion_matrix["FN"] += 1

        # Color-coded output
        color = "green" if is_correct else "red"
        print(colored(
            f"Level {level} | {result['method']} {payload} -> Expected: {expected}, Actual: {actual} (Correct: {is_correct})",
            color,
        ))

    # Calculate metrics
    tp, fp, tn, fn = confusion_matrix["TP"], confusion_matrix["FP"], confusion_matrix["TN"], confusion_matrix["FN"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0

    # Display final metrics
    print("\nFinal Statistics:")
    print(f"  Total Tests: {len(results)}")
    print(f"  Accuracy: {accuracy * 100:.2f}%")
    print(f"  Precision: {precision * 100:.2f}%")
    print(f"  Recall: {recall * 100:.2f}%")
    print(f"  F1 Score: {f1_score * 100:.2f}%")
    print("\nConfusion Matrix:")
    print(f"  True Positives (TP): {tp}")
    print(f"  False Positives (FP): {fp}")
    print(f"  True Negatives (TN): {tn}")
    print(f"  False Negatives (FN): {fn}")

# Main execution
if __name__ == "__main__":
    args = parse_args()
    test_cases = generate_test_cases(args.num_tests)
    results = execute_tests(args.host, test_cases)
    display_results(results)
