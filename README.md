# Caddy ML WAF (caddy-mlf)

[![Go](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml) [![CodeQL](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/github-code-scanning/codeql)

This Caddy module is a simulated ML-based WAF that analyzes HTTP requests, calculates anomaly scores, and flags or blocks threats. It offers customizable thresholds, dynamic behavior, and adapts to web app needs for flexible, real-time threat detection.

## Features

- **🕵️ Anomaly Detection**: Scans request size, headers, query params, path segments, methods, agents, referrers, and request frequency.  
- **🔗 Request Correlation**: Tracks client IP request history.  
- **🎯 Customizable Thresholds**: Set `anomaly_threshold` to flag suspicious requests.  
- **📂 Per-Path Config**: Define unique thresholds for specific paths via `per_path_config`.  
- **⚖️ Flexible Weighting**: Prioritize impact by weighting request attributes (e.g., size, headers, frequency).  
- **🌐 Dynamic Behavior**: Adapts to traffic changes & attack patterns.  
- **📊 Request History Mgmt**: Control data retention with `history_window` & `max_history_entries`.  
- **💡 Lightweight**: Efficient & minimal resource usage.  

---

## New Feature: Request Frequency Weight

The latest version of `caddy-mlf` introduces a **request frequency weight** feature. This allows the module to detect and mitigate bursts of requests from the same client, which are often indicative of brute force attacks, DDoS attempts, or scanning activities.

### How It Works:
- The module tracks the number of requests from each client IP within the configured `history_window`.
- If the frequency of requests exceeds normal behavior, the anomaly score is increased based on the `request_frequency_weight`.
- This feature helps detect and block high-frequency attacks while allowing legitimate traffic.

### Example Configuration:
```caddyfile
ml_waf {
    anomaly_threshold 0.5
    blocking_threshold 0.7

    # Normal ranges for request attributes
    normal_request_size_range 50 5000
    normal_header_count_range 3 25
    normal_query_param_count_range 0 10
    normal_path_segment_count_range 1 5

    # Additional attributes
    normal_http_methods GET POST
    normal_user_agents fab Mozilla
    normal_referrers https://example.com

    # Weights (sum = 1)
    request_size_weight 0.25
    header_count_weight 0.2
    query_param_count_weight 0.15
    http_method_weight 0.1
    user_agent_weight 0.1
    referrer_weight 0.05
    path_segment_count_weight 0.05
    request_frequency_weight 0.1  # New: Weight for request frequency

    # Request history settings
    history_window 5m
    max_history_entries 10000
}
```

---

## Updated Configuration Options

### `request_frequency_weight`
* **Description:** Assigns a weight to the frequency of requests from the same client IP. Higher weights increase the impact of request bursts on the anomaly score.
* **Data Type:** `float`
* **Default:** `0.0` (disabled by default)
* **Example:**
    ```caddyfile
    ml_waf {
        request_frequency_weight 0.1
    }
    ```

---

## Updated Use Cases

### 1. **Detecting and Blocking Brute Force Attacks**
Brute force attacks involve a high volume of requests from the same IP address in a short period. The `request_frequency_weight` feature helps detect and block such behavior.

```caddy
ml_waf {
    anomaly_threshold 0.8
    blocking_threshold 0.95

    request_frequency_weight 0.2  # Increased weight for request frequency
    history_window 1m
    max_history_entries 20

    request_size_weight 0.2
    header_count_weight 0.2
    query_param_count_weight 0.2
    path_segment_count_weight 0.2
    http_method_weight 0.1
    user_agent_weight 0.1
}
```

**Explanation:**
- **`request_frequency_weight 0.2`**: Assigns a significant weight to request frequency, making it a key factor in detecting brute force attacks.
- **`history_window 1m`**: Analyzes requests from the last minute to detect high-frequency patterns.
- **`max_history_entries 20`**: Limits the number of requests from a single IP address within the history window.

---

### 2. **Mitigating DDoS Attacks**
Distributed Denial of Service (DDoS) attacks often involve a flood of requests from multiple IPs. The `request_frequency_weight` feature can help mitigate such attacks by detecting unusual request patterns.

```caddy
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
- **`request_frequency_weight 0.15`**: Assigns a moderate weight to request frequency, balancing detection and false positives.
- **`history_window 10m`**: Analyzes requests over a longer period to detect sustained attack patterns.
- **`max_history_entries 100`**: Tracks a larger number of requests to identify distributed attacks.

---

### 3. **Preventing Scanning Activities**
Attackers often use automated tools to scan for vulnerabilities. The `request_frequency_weight` feature can detect and block such scanning activities.

```caddy
ml_waf {
    anomaly_threshold 0.6
    blocking_threshold 0.85

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
- **`request_frequency_weight 0.1`**: Assigns a lower weight to request frequency, focusing more on individual request attributes.
- **`history_window 5m`**: Analyzes requests from the last 5 minutes to detect scanning patterns.
- **`max_history_entries 50`**: Limits the number of requests from a single IP address within the history window.

---

## Updated How It Works

The `caddy-mlf` module now includes the following steps in its operation:

1. **Extracts Attributes**: Extracts attributes from each incoming request, such as request size, header count, query parameters, path segments, HTTP method, User-Agent, Referrer, and request frequency.
2. **Calculates Anomaly Score**: Compares these attributes to configured normal ranges and calculates an anomaly score using the specified weights, including the new `request_frequency_weight`.
3. **Retrieves Request History**: Retrieves recent request history for the client IP, leveraging historical data to adjust the anomaly score based on past behavior.
4. **Takes Action**: Takes action based on the final score:
   * If the score meets or exceeds the `blocking_threshold`, the request is blocked.
   * If the score is above the `anomaly_threshold` but below the `blocking_threshold`, the request is marked as suspicious by adding a `X-Suspicious-Traffic` header.
5. **Allows Legitimate Traffic**: Allows non-suspicious requests to proceed to the next middleware or handler in the chain.

---

## Updated Example Configuration

Here’s an example configuration that includes the new `request_frequency_weight` feature:

```caddyfile
{
    admin off
    order ml_waf before respond
    log {
        level debug
    }
}

:8082 {
    handle {
        ml_waf {
            # Thresholds
            anomaly_threshold 0.5
            blocking_threshold 0.7

            # Normal ranges for request attributes
            normal_request_size_range 50 5000
            normal_header_count_range 3 25
            normal_query_param_count_range 0 10
            normal_path_segment_count_range 1 5

            # Additional attributes
            normal_http_methods GET POST
            normal_user_agents fab Mozilla
            normal_referrers https://example.com

            # Weights (sum = 1)
            request_size_weight 0.25
            header_count_weight 0.2
            query_param_count_weight 0.15
            http_method_weight 0.1
            user_agent_weight 0.1
            referrer_weight 0.05
            path_segment_count_weight 0.05
            request_frequency_weight 0.1  # New: Weight for request frequency

            # Request history settings
            history_window 5m
            max_history_entries 10000

            # Per-path configuration for /api
            per_path_config /api {
                anomaly_threshold 0.2
                blocking_threshold 0.4
            }
        }
        respond "Hello, world!" 200
    }
}
```

---

## Contributing

Contributions to the `caddy-mlf` module are welcome! 

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
