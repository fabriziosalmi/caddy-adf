# Caddy ML WAF (caddy-mlf)

[![Go](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml)
[![CodeQL](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/github-code-scanning/codeql)

`caddy-mlf` is a Caddy middleware module that provides a simulated Machine Learning-based Web Application Firewall (WAF). It analyzes incoming HTTP requests, calculates anomaly scores based on various request attributes, and can flag or block suspicious traffic. It's designed for flexible, real-time threat detection and can be customized to fit various web application needs.

## Features

-   **🤖 Simulated ML Anomaly Detection**: Analyzes request size, headers, query parameters, path segments, HTTP methods, User-Agents, Referrers, and request frequency to identify anomalous patterns.
-   **🔗 Request Correlation**: Leverages client IP request history to identify potentially malicious patterns over time, enhancing detection accuracy.
-   **🚦 Configurable Thresholds**:
    -   `anomaly_threshold`:  Flags requests with an anomaly score above this value as suspicious.
    -   `blocking_threshold`: Blocks requests with an anomaly score above this value.
-   **📁 Per-Path Configurations**: Allows you to define unique anomaly and blocking thresholds for specific paths, offering more granular control.
-   **⚖️ Customizable Weighting**: Provides fine-grained control over how each attribute contributes to the overall anomaly score.
-   **⏱️ Dynamic Analysis**: Adapts to changes in traffic and attack patterns based on configurable history window and maximum history entries.
-   **⚡ Lightweight and Efficient**: Designed to have minimal impact on performance.
-   **🛡️ Protection against common attacks**: Helps protect against brute force, DDoS, scanning and other malicious activities.

---

## How it Works

`caddy-mlf` operates by:

1.  **Attribute Extraction:** Extracting attributes from each incoming HTTP request, such as the request size, header count, query parameters, path segments, HTTP method, User-Agent, Referrer, and request frequency.
2.  **Anomaly Score Calculation:** Calculating an anomaly score based on configured weights, comparing request attributes to the defined "normal" ranges and behaviors. The score considers factors like request size, header and parameter counts, path segments, method, agent, referrer and request frequency.
3.  **Request History Tracking:** Maintains a history of requests for each client IP within a configurable time window, enabling detection of suspicious patterns over time and request correlation.
4.  **Threshold-Based Action:** Taking action based on the calculated anomaly score:
    *   **Blocking:** If the anomaly score meets or exceeds the `blocking_threshold`, the request is blocked with a 403 Forbidden response.
    *   **Marking as Suspicious:** If the anomaly score is above the `anomaly_threshold` but below the `blocking_threshold`, the request is marked as suspicious by adding an `X-Suspicious-Traffic: true` header to the response.
5.  **Normal Request Processing:** Allowing normal requests to proceed to the next middleware or handler.

## Caddyfile Configuration

Here's an example Caddyfile configuration for `caddy-mlf`:

```caddyfile
{
    admin off
    log {
        level debug
    }
    order ml_waf before respond
}

:8082 {
    handle {
        ml_waf {
            # Thresholds
            anomaly_threshold 0.3
            blocking_threshold 0.6

            # Normal ranges for request attributes
            normal_request_size_range 100 4000
            normal_header_count_range 5 20
            normal_query_param_count_range 0 10
            normal_path_segment_count_range 1 5

            # Additional attributes
            normal_http_methods GET POST PUT DELETE OPTIONS
            normal_user_agents fab Mozilla Chrome
            normal_referrers https://example.com https://trusted.example.org

            # Weights for each attribute
            request_size_weight 0.25
            header_count_weight 0.20
            query_param_count_weight 0.15
            path_segment_count_weight 0.10
            http_method_weight 0.10
            user_agent_weight 0.10
            referrer_weight 0.05
            request_frequency_weight 0.05

            # Request history settings
            history_window 5m
            max_history_entries 1000

            # Per-path configuration
            per_path_config /api {
                anomaly_threshold 0.15
                blocking_threshold 0.4
            }

            per_path_config /admin {
                 anomaly_threshold 0.05
                 blocking_threshold 0.1
             }
        }
        respond "Hello, world!" 200
    }
}
```

## Configuration Options

### Global Options

-   **`anomaly_threshold`**: `float` (default: `0.0`). The threshold at which a request is considered suspicious. A value between 0 and 1 is recommended.
-   **`blocking_threshold`**: `float` (default: `0.0`). The threshold at which a request is blocked. This value must be greater than `anomaly_threshold`. A value between 0 and 1 is recommended.
-   **`normal_request_size_range`**: `int int`. Defines the normal range of request sizes (in bytes) `min max`.
-   **`normal_header_count_range`**: `int int`. Defines the normal range for the number of headers in a request `min max`.
-   **`normal_query_param_count_range`**: `int int`. Defines the normal range for the number of query parameters in a request `min max`.
-   **`normal_path_segment_count_range`**: `int int`. Defines the normal range for the number of segments in a request path `min max`.
-   **`normal_http_methods`**: `string...`.  A list of HTTP methods considered normal (e.g., `GET`, `POST`).
-   **`normal_user_agents`**: `string...`. A list of User-Agent substrings considered normal.
-   **`normal_referrers`**: `string...`. A list of Referrer substrings considered normal.
-   **`request_size_weight`**: `float` (default: `1.0`). Weight for the request size in anomaly score calculation.
-   **`header_count_weight`**: `float` (default: `1.0`). Weight for the header count in anomaly score calculation.
-   **`query_param_count_weight`**: `float` (default: `1.0`). Weight for the query parameter count in anomaly score calculation.
-   **`path_segment_count_weight`**: `float` (default: `1.0`). Weight for the path segment count in anomaly score calculation.
-    **`http_method_weight`**: `float` (default: `0.0`). Weight to apply if a request's HTTP method is not within the `normal_http_methods` list.
-    **`user_agent_weight`**: `float` (default: `0.0`). Weight to apply if a request's User-Agent does not contain any of the `normal_user_agents` substrings.
-   **`referrer_weight`**: `float` (default: `0.0`). Weight to apply if a request's Referrer does not contain any of the `normal_referrers` substrings.
-   **`request_frequency_weight`**: `float` (default: `1.0`). Weight for the request frequency in anomaly score calculation.
-   **`history_window`**: `duration` (default: `1m`). Duration for which request history is kept.
-    **`max_history_entries`**: `int` (default: `10`). Maximum number of request history entries per client IP to store.

### Per-Path Configuration (`per_path_config`)

-   **`per_path_config <path> { ... }`**: Allows you to set different `anomaly_threshold` and `blocking_threshold` options for a specific path.
    -   **`anomaly_threshold`**: `float`.  Overrides the global `anomaly_threshold` for this path.
    -   **`blocking_threshold`**: `float`. Overrides the global `blocking_threshold` for this path.

## Use Cases and Examples

Here are some practical use cases with example configurations:

### 1. Detecting and Blocking Brute Force Attacks

```caddyfile
ml_waf {
    anomaly_threshold 0.6
    blocking_threshold 0.8

    request_frequency_weight 0.3 # increased weight for request frequency
    history_window 1m
    max_history_entries 50

    request_size_weight 0.2
    header_count_weight 0.2
    query_param_count_weight 0.2
    path_segment_count_weight 0.1
    http_method_weight 0.1
    user_agent_weight 0.1
}
```

**Explanation:**
- **`request_frequency_weight 0.3`**:  Emphasizes request frequency to detect rapid login attempts.
- **`history_window 1m`**: Tracks recent requests for quick detection.
- **`max_history_entries 50`**:  Limits the history to a reasonable amount.

### 2. Mitigating DDoS Attacks

```caddyfile
ml_waf {
    anomaly_threshold 0.7
    blocking_threshold 0.9

    request_frequency_weight 0.15  # Moderate weight for request frequency
    history_window 10m
    max_history_entries 100

    request_size_weight 0.25
    header_count_weight 0.2
    query_param_count_weight 0.15
    path_segment_count_weight 0.1
    http_method_weight 0.1
    user_agent_weight 0.1
    referrer_weight 0.05
}
```

**Explanation:**
-   **`request_frequency_weight 0.15`**:  A moderate weight is assigned for request frequency.
-   **`history_window 10m`**:  Examines traffic over a longer period for distributed attacks.
-   **`max_history_entries 100`**: A larger history is kept for identifying larger attacks.

### 3. Preventing Scanning Activities

```caddyfile
ml_waf {
    anomaly_threshold 0.5
    blocking_threshold 0.8

    request_frequency_weight 0.1  # Lower weight for request frequency
    history_window 5m
    max_history_entries 50

    request_size_weight 0.3
    header_count_weight 0.25
    query_param_count_weight 0.2
    path_segment_count_weight 0.15
    http_method_weight 0.1
}
```

**Explanation:**
-   **`request_frequency_weight 0.1`**:  Reduces the focus on frequency, emphasizing other request features.
-   **`history_window 5m`**:  Tracks requests over a moderate window for scanning activity.
-   **`max_history_entries 50`**: Keeps a reasonable history size.

## Contributing

Contributions to `caddy-mlf` are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
