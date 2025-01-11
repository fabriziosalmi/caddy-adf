# Caddy ML WAF (caddy-mlf)

[![Go](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml)
[![CodeQL](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/github-code-scanning/codeql)

`caddy-mlf` is a Caddy middleware module providing a simulated Machine Learning-based Web Application Firewall (WAF). It analyzes incoming HTTP requests, calculates anomaly scores based on various attributes, and can flag or block suspicious traffic. It's designed for flexible, real-time threat detection and can be customized to fit a wide range of web application needs.

## Table of Contents

1.  [Installation](#installation)
2.  [Features](#features)
3.  [How it Works](#how-it-works)
    *   [Scoring Mechanism](#scoring-mechanism)
4.  [Caddyfile Configuration](#caddyfile-configuration)
5.  [Configuration Options](#configuration-options)
    *   [Global Options](#global-options)
    *   [Per-Path Configuration](#per-path-configuration-per_path_config)
6.  [Use Cases and Examples](#use-cases-and-examples)
    *   [1. Detecting and Blocking Brute Force Attacks](#1-detecting-and-blocking-brute-force-attacks)
    *   [2. Mitigating DDoS Attacks](#2-mitigating-ddos-attacks)
    *   [3. Preventing Scanning Activities](#3-preventing-scanning-activities)
    *   [4. Protecting Specific Endpoints](#4-protecting-specific-endpoints)
7.  [Advanced Configuration](#advanced-configuration)
    *   [Tuning Weights](#tuning-weights)
    *   [Fine-Tuning Thresholds](#fine-tuning-thresholds)
    *   [Understanding Request History](#understanding-request-history)
8.  [Troubleshooting](#troubleshooting)
    *   [Detailed Debugging](#detailed-debugging)
    *   [Common Issues](#common-issues)
9.  [Contributing](#contributing)
10. [License](#license)

## 1. Installation

To use `caddy-mlf`, you need to have Caddy v2 installed. Follow these steps to install the module:

1.  **Download the module:** You can download the pre-compiled module or build it yourself.

    *   **Pre-compiled (Recommended):** Download the binary from the [releases page](https://github.com/fabriziosalmi/caddy-mlf/releases). Place the binary in the Caddy modules directory (usually `~/.config/caddy/modules` or `/usr/local/lib/caddy/modules/`).
    *   **Build from source:**
        ```bash
        git clone https://github.com/fabriziosalmi/caddy-mlf
        cd caddy-mlf
        xcaddy build --with github.com/fabriziosalmi/caddy-mlf
        ```
        Place the resulting binary in the Caddy modules directory (usually `~/.config/caddy/modules` or `/usr/local/lib/caddy/modules/`).
2.  **Update your Caddyfile**: Configure the `caddy-mlf` directive within your Caddyfile as shown below.
3.  **Start Caddy:** Restart or reload Caddy to apply the changes.

## 2. Features

-   **🤖 Simulated ML Anomaly Detection**: Analyzes request size, headers, query parameters, path segments, HTTP methods, User-Agents, Referrers, and request frequency to identify anomalous patterns.
-   **🔗 Request Correlation**: Leverages client IP request history to identify potentially malicious patterns over time, enhancing detection accuracy.
-   **🚦 Configurable Thresholds**:
    -   `anomaly_threshold`: Flags requests with an anomaly score above this value as suspicious.
    -   `blocking_threshold`: Blocks requests with an anomaly score above this value.
-   **📁 Per-Path Configurations**: Allows you to define unique anomaly and blocking thresholds for specific paths, offering more granular control.
-   **⚖️ Customizable Weighting**: Provides fine-grained control over how each attribute contributes to the overall anomaly score.
-   **⏱️ Dynamic Analysis**: Adapts to changes in traffic and attack patterns based on configurable history window and maximum history entries.
-   **⚡ Lightweight and Efficient**: Designed to have minimal impact on performance.
-   **🛡️ Protection against common attacks**: Helps protect against brute force, DDoS, scanning, and other malicious activities.
-   **🎛️ Redaction:** Automatically redacts sensitive headers and query parameters such as `Authorization`, `Cookie`, `Set-Cookie`, `token`, `password`, `api_key`.

---

## 3. How it Works

`caddy-mlf` operates by:

1.  **Attribute Extraction:** Extracting attributes from each incoming HTTP request, such as the request size, header count, query parameters, path segments, HTTP method, User-Agent, Referrer, and request frequency.
2.  **Anomaly Score Calculation:** Calculating an anomaly score based on configured weights, comparing request attributes to the defined "normal" ranges and behaviors. The score considers factors like request size, header and parameter counts, path segments, method, agent, referrer and request frequency, using configurable weights.
3.  **Request History Tracking:** Maintains a history of requests for each client IP within a configurable time window, enabling detection of suspicious patterns over time and request correlation. This history is sharded to optimize performance.
4.  **Threshold-Based Action:** Taking action based on the calculated anomaly score:
    *   **Blocking:** If the anomaly score meets or exceeds the `blocking_threshold`, the request is blocked with a 403 Forbidden response.
    *   **Marking as Suspicious:** If the anomaly score is above the `anomaly_threshold` but below the `blocking_threshold`, the request is marked as suspicious by adding an `X-Suspicious-Traffic: true` header to the response.
5.  **Normal Request Processing:** Allowing normal requests to proceed to the next middleware or handler in the chain.

### Scoring Mechanism

The anomaly score is calculated by combining normalized attribute scores with their corresponding weights:

1.  **Normalization:** Each attribute (request size, header count, query parameter count, path segment count) is normalized based on its configured `min` and `max` range.
    - If the value is within the normal range, the normalized value is `0.0`.
    - If the value is less than the minimum, the value is the positive ratio of the difference from the minimum, divided by `(min + 1)`.
    - If the value is greater than the maximum, the value is the natural logarithm of the difference from the maximum, divided by `(max + 1) + 1`.
2.  **Weighting:** Each normalized attribute is multiplied by its respective weight (`request_size_weight`, `header_count_weight`, etc.).
3.  **Frequency Score:** If `request_frequency_weight` is set, the request frequency over the `history_window` is calculated and multiplied by the frequency weight.
4.  **Method, User-Agent, Referrer Scores:** Requests that do not match the defined `normal_http_methods`, `normal_user_agents`, and `normal_referrers` will be penalized by the weights: `http_method_weight`, `user_agent_weight`, and `referrer_weight`.
5.  **Correlation Score:** The history is checked for previous suspicious requests (above `anomaly_threshold`). A correlation score is added, giving more weight to suspicious traffic that is part of a correlated pattern over time.
6.  **Total Score:** The weighted, normalized values are summed up to create the final anomaly score.

## 4. Caddyfile Configuration

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

## 5. Configuration Options

### Global Options

| Option                       | Type        | Default | Description                                                                                                                                                                    |
| ---------------------------- | ----------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `anomaly_threshold`          | `float`     | `0.0`   | The threshold at which a request is considered suspicious. A value between 0 and 1 is recommended.                                                                           |
| `blocking_threshold`         | `float`     | `0.0`   | The threshold at which a request is blocked. This value must be greater than `anomaly_threshold`. A value between 0 and 1 is recommended.                                   |
| `normal_request_size_range`  | `int int`   |         | Defines the normal range of request sizes (in bytes) `min max`. Requests outside this range will contribute to the anomaly score.                                         |
| `normal_header_count_range`  | `int int`   |         | Defines the normal range for the number of headers in a request `min max`. Requests with header counts outside this range will contribute to the anomaly score.              |
| `normal_query_param_count_range`| `int int` |         | Defines the normal range for the number of query parameters in a request `min max`. Requests with query parameter counts outside this range will contribute to the anomaly score. |
| `normal_path_segment_count_range`| `int int` |         | Defines the normal range for the number of segments in a request path `min max`. Requests with path segment counts outside this range will contribute to the anomaly score.   |
| `normal_http_methods`        | `string...` |         | A list of HTTP methods considered normal (e.g., `GET`, `POST`). Requests using methods not in this list will be penalized based on `http_method_weight`.                       |
| `normal_user_agents`         | `string...` |         | A list of User-Agent substrings considered normal. Requests with User-Agents that do not contain any of these substrings will be penalized based on `user_agent_weight`.      |
| `normal_referrers`           | `string...` |         | A list of Referrer substrings considered normal. Requests with Referrers that do not contain any of these substrings will be penalized based on `referrer_weight`.            |
| `request_size_weight`        | `float`     | `1.0`   | Weight for the request size in the anomaly score calculation. Adjust this to prioritize the impact of request size variations. Increase this to penalize unusual request sizes.   |
| `header_count_weight`        | `float`     | `1.0`   | Weight for the header count in the anomaly score calculation. Increase this to emphasize requests with unusual header counts.                                               |
| `query_param_count_weight`   | `float`     | `1.0`   | Weight for the query parameter count in the anomaly score calculation. Increase this to emphasize requests with unusual query parameter counts.                               |
| `path_segment_count_weight`  | `float`     | `1.0`   | Weight for the path segment count in the anomaly score calculation. Increase this to emphasize requests with unusual path segment counts.                                  |
| `http_method_weight`         | `float`     | `0.0`   | Weight to apply if a request's HTTP method is not within the `normal_http_methods` list. Useful to penalize unusual HTTP methods.                                           |
| `user_agent_weight`          | `float`     | `0.0`   | Weight to apply if a request's User-Agent does not contain any of the `normal_user_agents` substrings. Useful to penalize requests with unusual User-Agents.                  |
| `referrer_weight`           | `float`     | `0.0`   | Weight to apply if a request's Referrer does not contain any of the `normal_referrers` substrings. Useful to penalize requests with unusual Referrers.                        |
| `request_frequency_weight`   | `float`     | `1.0`   | Weight for the request frequency in the anomaly score calculation. Increasing this makes the module more sensitive to high request rates from the same client.                 |
| `history_window`             | `duration`  | `1m`    | Duration for which request history is kept. Increase this for longer-term behavior analysis and decreased for shorter-term analysis.                                         |
| `max_history_entries`        | `int`       | `10`    | Maximum number of request history entries per client IP to store. Adjust based on the `history_window` and the volume of traffic you expect to process.                        |

### Per-Path Configuration (`per_path_config`)

-   **`per_path_config <path> { ... }`**: Allows you to set different `anomaly_threshold` and `blocking_threshold` options for a specific path.
    -   **`anomaly_threshold`**: `float`. Overrides the global `anomaly_threshold` for this path.
    -   **`blocking_threshold`**: `float`. Overrides the global `blocking_threshold` for this path.

## 6. Use Cases and Examples

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

-   `request_frequency_weight 0.3`: Emphasizes request frequency to detect rapid login attempts.
-   `history_window 1m`: Tracks recent requests for quick detection.
-   `max_history_entries 50`: Limits the history to a reasonable amount.

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

-   `request_frequency_weight 0.15`: A moderate weight is assigned for request frequency.
-   `history_window 10m`: Examines traffic over a longer period for distributed attacks.
-   `max_history_entries 100`: A larger history is kept for identifying larger attacks.

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

-   `request_frequency_weight 0.1`: Reduces the focus on frequency, emphasizing other request features.
-   `history_window 5m`: Tracks requests over a moderate window for scanning activity.
-   `max_history_entries 50`: Keeps a reasonable history size.

### 4. Protecting Specific Endpoints

```caddyfile
ml_waf {
    anomaly_threshold 0.4
    blocking_threshold 0.7

    request_frequency_weight 0.2
    history_window 5m
    max_history_entries 100

    request_size_weight 0.2
    header_count_weight 0.2
    query_param_count_weight 0.2
    path_segment_count_weight 0.2
    http_method_weight 0.1
    user_agent_weight 0.1

    per_path_config /admin {
        anomaly_threshold 0.1
        blocking_threshold 0.3
    }

    per_path_config /sensitive-api {
        anomaly_threshold 0.2
        blocking_threshold 0.4
    }
}
```

**Explanation:**

-   Global thresholds are set for general protection.
-   `per_path_config` is used to apply stricter thresholds for sensitive paths like `/admin` and `/sensitive-api`.

## 7. Advanced Configuration

### Tuning Weights

The `caddy-mlf` module uses weights to determine the contribution of different request attributes to the anomaly score. These weights allow you to customize the module's sensitivity to various aspects of incoming requests. Effective weight tuning is crucial for achieving a balance between security and usability.

-   **Increase weights** for attributes that are more indicative of malicious activity for your application. For example:
    *   If your application is often targeted by brute-force attacks with large request sizes, increase `request_size_weight`.
    *   If you see attacks using unusual headers, increase `header_count_weight`.
    *    If you have an API with a well-defined set of methods, increase `http_method_weight`.
    *    If your legitimate users use well-known user-agents, increase `user_agent_weight`.
-   **Decrease weights** for attributes that are less relevant to security in your specific scenario. For example:
    *   If your application handles a lot of large data uploads that are not typically malicious, decrease `request_size_weight`.
    *   If you have a lot of legitimate requests with varying numbers of query parameters, decrease `query_param_count_weight`.
-   **Start with small values:** When tuning weights, start with small adjustments and monitor how these changes affect your anomaly scores. Don't make drastic changes immediately.
-   **Normalize your weights:** While not strictly required, consider normalizing your weights so that their total is a manageable number (e.g., summing up to 1.0 or 100). This can make it easier to reason about how much influence each attribute has on the total score. For example, if you want request size to be half of the score and header count the other half, you can set both to `0.5` (assuming other weights are zeroed or are less important).

    ```caddyfile
    ml_waf {
        request_size_weight  0.5  # Emphasize request size
        header_count_weight  0.3  # Emphasize header count
        query_param_count_weight 0.1
        path_segment_count_weight 0.1
        # ... other weights
    }
    ```

### Fine-Tuning Thresholds

Thresholds determine when a request is considered suspicious or is blocked. Setting these values correctly is vital for minimizing false positives and false negatives.

-   **Start with conservative thresholds:** Begin with higher `anomaly_threshold` and `blocking_threshold` values to minimize false positives. This means that initially, the module will only flag or block highly unusual requests. For example, you might set an `anomaly_threshold` of `0.6` and `blocking_threshold` of `0.8` initially, and gradually reduce these as needed.

    ```caddyfile
     ml_waf {
       anomaly_threshold 0.6
       blocking_threshold 0.8
       # ... other options
     }
     ```

-   **Monitor logs:** Regularly check your Caddy logs (especially in `debug` mode) for suspicious requests or blocked requests. This will give you data to understand if you need to adjust your thresholds. Pay particular attention to the anomaly score and the context of each request.
-   **Adjust incrementally:** Fine-tune the thresholds gradually based on the observed behavior. For example:
    *   If you see too many legitimate requests marked as suspicious, lower your `anomaly_threshold`.
    *   If you see malicious requests getting through, lower your `blocking_threshold`.
-   **Use per-path configurations** to apply tighter rules to more sensitive parts of your application. For instance:

    ```caddyfile
        ml_waf {
            anomaly_threshold 0.4      # Global settings
            blocking_threshold 0.7

            per_path_config /admin {
                anomaly_threshold 0.1   # Stricter settings for /admin path
                blocking_threshold 0.2
            }
        }
    ```

-   **Consider environment:** The right thresholds might depend on your environment and application. A more security-critical application might require lower thresholds and more aggressive rules compared to a low-impact application.

### Understanding Request History

The request history mechanism helps to identify patterns of attack and correlate suspicious behavior over time. It allows the module to adapt and flag continuous patterns of malicious traffic coming from the same IPs. Here's how to best utilize it:

-   **`history_window`:** Set this value based on your observation window. If your application needs quick reaction times to attacks that occur in short bursts, shorten the window. For slower attacks (like scanning activities or low-frequency brute-force attempts), keep a longer window.
    *   **Short Window (e.g., 1-5 minutes):** Suitable for quickly detecting and reacting to sudden spikes in activity, such as brute-force login attempts.

        ```caddyfile
        ml_waf {
            history_window 2m
            # ... other options
        }
        ```
    *   **Longer Window (e.g., 10+ minutes):** Better for detecting distributed attacks or slow scanning behavior that might not be obvious over a short time.

        ```caddyfile
         ml_waf {
             history_window 20m
             # ... other options
         }
        ```
-   **`max_history_entries`:** Adjust the number of entries based on traffic volume and your system's memory capabilities.
    *   **Lower values:** Use lower values when dealing with high traffic to avoid high memory usage. This will keep the memory footprint small.
    *   **Higher values:** Use higher values if you have low traffic and want to be able to track more requests. This is useful when looking for very specific attack patterns. Be aware that this can consume more memory.

        ```caddyfile
            ml_waf {
                max_history_entries 500
                # ... other options
            }
        ```
-   **Monitor:** Keep an eye on your logs, where information about the history and anomaly score of every request is logged using the `debug` level. Look for patterns in anomaly scores over time for specific IPs to get insights into the behavior of potential attackers.
-   **Adjust history along with request frequency:** When you tune `request_frequency_weight`, you should adjust `history_window` and `max_history_entries` to match your expected traffic and attack patterns. A very high `request_frequency_weight` will probably need a lower history window and fewer entries.

## 8. Troubleshooting

### Detailed Debugging

To get the most out of troubleshooting, use the `debug` log level in your Caddyfile:

```caddyfile
{
    log {
        level debug
    }
    # ... other global options
}
```

This provides detailed information about each request, the calculated anomaly scores, and any decisions made by `caddy-mlf`.

### Common Issues

1.  **False Positives:** If legitimate requests are being flagged as suspicious, try:
    *   Increasing the `anomaly_threshold` and/or `blocking_threshold`.
    *   Adjusting `normal_*_range` values to match normal traffic patterns.
    *   Reviewing the weights to ensure they accurately reflect the importance of different parameters.

2.  **Requests Not Being Blocked:** If malicious requests are not being blocked, try:
    *   Decreasing the `anomaly_threshold` and/or `blocking_threshold`.
    *   Increasing the weights to emphasize attack indicators.
    *   Verifying that the configuration is loaded and that the module is correctly placed in the Caddy middleware chain.

3.  **Performance Issues:** If you notice performance degradation, try:
    *   Reducing the `history_window`.
    *   Lowering the `max_history_entries`.
    *   Optimizing your Caddy configuration.
    *   Ensuring that your system has adequate resources.

4.  **Module Not Loaded:** If the module doesn't work, ensure the module binary is placed correctly and that Caddy is restarted correctly.

## 9. Contributing

Contributions to `caddy-mlf` are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 10. License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
