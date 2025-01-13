# Caddy ADF (Anomaly Detection Filter)

[![Go](https://github.com/fabriziosalmi/caddy-adf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-adf/actions/workflows/go.yml)
[![CodeQL](https://github.com/fabriziosalmi/caddy-adf/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/fabriziosalmi/caddy-adf/actions/workflows/github-code-scanning/codeql)

`caddy-adf` is a Caddy middleware module providing a simulated Machine Learning-based Web Application Firewall (WAF). It analyzes incoming HTTP requests, calculates anomaly scores based on various attributes, and can flag or block suspicious traffic. It's designed for flexible, real-time threat detection and can be customized to fit a wide range of web application needs.

## Table of Contents

1.  [Installation](#installation)
2.  [Features](#features)
3.  [How it Works](#how-it-works)
    *   [Attribute Extraction](#attribute-extraction)
    *   [Scoring Mechanism](#scoring-mechanism)
        *   [Traditional Score](#traditional-score)
        *   [ML Score](#ml-score)
    *   [Request History Tracking](#request-history-tracking)
    *   [Request Redaction](#request-redaction)
    *   [Threshold-Based Action](#threshold-based-action)
        *   [Dynamic Thresholds](#dynamic-thresholds)
        *   [Default Path Configuration](#default-path-configuration)
4.  [Caddyfile Configuration](#caddyfile-configuration)
5.  [Configuration Options](#configuration-options)
    *   [Global Options](#global-options)
    *   [Normalization Configuration](#normalization-configuration)
    *   [Per-Path Configuration](#per-path-configuration)
        *   [Default Path Configuration](#default-path-configuration-1)
6.  [Use Cases and Examples](#use-cases-and-examples)
    *   [1. Detecting and Blocking Brute Force Attacks](#1-detecting-and-blocking-brute-force-attacks)
    *   [2. Mitigating DDoS Attacks](#2-mitigating-ddos-attacks)
    *   [3. Preventing Scanning Activities](#3-preventing-scanning-activities)
    *   [4. Protecting Specific Endpoints](#4-protecting-specific-endpoints)
7.  [Advanced Configuration](#advanced-configuration)
    *   [Admin Endpoint](#admin-endpoint)
        *   [Update Model Endpoint](#update-model-endpoint)
        *   [Get Config Endpoint](#get-config-endpoint)
    *   [Tuning Weights](#tuning-weights)
    *   [Fine-Tuning Thresholds](#fine-tuning-thresholds)
        *   [Dynamic Thresholds](#dynamic-thresholds-1)
    *   [Understanding Request History](#understanding-request-history)
8.  [Troubleshooting](#troubleshooting)
    *   [Detailed Debugging](#detailed-debugging)
     *   [Specific Error Messages](#specific-error-messages)
    *   [Common Issues](#common-issues)
9.  [Contributing](#contributing)
10. [License](#license)

## 1. Installation

To use `caddy-adf`, you need to have Caddy v2 adn xcaddy already installed. Follow these steps to install the module:

1.  **Quick Start:** You can download the pre-compiled module or build it yourself.

    *   **Build from source and run:**
        ```bash
        git clone https://github.com/fabriziosalmi/caddy-adf
        cd caddy-adf
        xcaddy build --with github.com/fabriziosalmi/caddy-adf=./
        ./caddy run
        ```


## 2. Features

-   **🤖 Anomaly Detection**: Analyzes request size, headers, query parameters, path segments, HTTP methods, User-Agents, and Referrers to identify anomalous patterns.
-   **🔗 Request Correlation**: Leverages client IP request history to identify potentially malicious patterns over time, enhancing detection accuracy.
-   **🚦 Configurable Thresholds**:
    -   `anomaly_threshold`: Flags requests with an anomaly score above this value as suspicious.
    -   `blocking_threshold`: Blocks requests with an anomaly score above this value.
-   **📁 Per-Path Configurations**: Allows you to define unique anomaly and blocking thresholds for specific paths, offering more granular control.
-   **🗂️ Default Per-Path Configurations:** Set a default configuration for all paths that do not have a specific configuration.
-    **🎛️ Flexible Normalization:** You can choose between linear or log normalization methods for individual attributes.
-   **⚖️ Customizable Weighting**: Provides fine-grained control over how each attribute contributes to the overall anomaly score.
-   **⏱️ Dynamic Analysis**: Adapts to changes in traffic and attack patterns based on configurable history window and maximum history entries.
-   **⚡ Lightweight and Efficient**: Designed to have minimal impact on performance.
-   **🛡️ Protection against common attacks**: Helps protect against brute force, DDoS, scanning, and other malicious activities.
 -   **🛡️ Redaction:** Automatically redacts sensitive headers and query parameters based on regex, such as `Authorization`, `Cookie`, `Set-Cookie`, `token`, `password`, and `api_key`.
-   **⚙️ ML Model Update at Runtime**: You can update the model at runtime without restarting Caddy.
-    **📈 Get Config Endpoint**: You can get the current configuration using an endpoint that returns JSON.

---

## 3. How it Works

`caddy-adf` operates by:

### Attribute Extraction

The middleware extracts several attributes from each incoming HTTP request, such as:

*   `requestSize`: The size of the request body in bytes.
*   `headerCount`: The number of headers present in the request.
*   `queryParamCount`: The number of query parameters in the request URL.
*  `pathSegmentCount`: The number of segments in the URL path.
*   `httpMethod`: The HTTP method used (e.g., GET, POST, PUT).
*   `userAgent`: The value of the `User-Agent` header.
*   `referrer`: The value of the `Referer` header.

### Scoring Mechanism

The anomaly score is calculated by combining normalized attribute scores with their corresponding weights.

#### Traditional Score

1.  **Normalization:** Each attribute (`requestSize`, `headerCount`, `queryParamCount`, and `pathSegmentCount`) is normalized based on its configured `min` and `max` range and a normalization function.
     * You can configure a `linear` or `log` normalization using the `normalization_config` option.
     *  If the value is within the normal range, the normalized value is `0.0`.
    * If the value is less than the minimum, the value is the positive ratio of the difference from the minimum, divided by `(min + 1)`.
    * If the value is greater than the maximum, the value is the natural logarithm of the difference from the maximum, divided by `(max + 1) + 1`.

2.  **Weighting:** Each normalized attribute is multiplied by its respective weight (`request_size_weight`, `header_count_weight`, etc.).
3.  **Frequency Score:** If `request_frequency_weight` is set, the request frequency over the `history_window` is calculated and multiplied by the frequency weight.
4.  **Method, User-Agent, Referrer Scores:** Requests that do not match the defined `normal_http_methods`, `normal_user_agents`, and `normal_referrers` will be penalized by the weights: `http_method_weight`, `user_agent_weight`, and `referrer_weight`.
5.  **Correlation Score:** The history is checked for previous suspicious requests (above `anomaly_threshold`). A correlation score is added, giving more weight to suspicious traffic that is part of a correlated pattern over time.

#### ML Score

1.  **Feature Extraction:** The request's attributes are processed by the ML model to extract different features. These features are calculated using helper methods, and transformed into keys that match the model dictionary.
2.  **Score Retrieval:** The model looks up scores corresponding to each feature based on a pre-trained model file.
3.  **Score Calculation:** If a feature is found in the dictionary, the score will be added, otherwise a `0.1` score is added by default.

### Request History Tracking

Maintains a history of requests for each client IP within a configurable time window, enabling detection of suspicious patterns over time and request correlation. This history is sharded to optimize performance.

### Request Redaction

The middleware sanitizes the requests by redacting sensitive headers and query parameters based on the provided lists using regular expressions for matching.

### Threshold-Based Action

The module takes actions based on the calculated anomaly score:

1.  **Anomaly Threshold Check**: If the anomaly score meets or exceeds the `anomaly_threshold`, the request is marked as suspicious by adding a `X-Suspicious-Traffic: true` header to the response.
2.  **Blocking Threshold Check:** If the `anomalyScore` is greater than or equal to the `blocking_threshold`, the request is blocked.
    * The middleware responds with a `403 Forbidden` error, the `X-ML-WAF-Blocked` header will be set to `true`, and the  `X-ML-WAF-Anomaly-Score` will contain the `anomalyScore` of the request.

#### Dynamic Thresholds

If dynamic thresholds are enabled, the `anomaly_threshold` is calculated based on a moving average of past threshold values for each path.

#### Default Path Configuration

If a `per_path_config` is not defined for a given path, the `default_path_config` will be used for that specific path.

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
            # Global Thresholds
            anomaly_threshold 0.2
            blocking_threshold 0.7

            # Normal Ranges for Request Attributes
            normal_request_size_range 100 5000
            normal_header_count_range 3 25
            normal_query_param_count_range 0 15
            normal_path_segment_count_range 1 7

            # Normal HTTP Methods, User Agents, and Referrers
            normal_http_methods GET POST PUT DELETE OPTIONS HEAD
            normal_user_agents Mozilla Chrome Safari python-requests/2.32.3 curl
            normal_referrers https://example.com https://trusted.example.org

            # Weights - Using a mix of traditional and ML
            request_size_weight 0.1
            header_count_weight 0.1
            query_param_count_weight 0.05
            path_segment_count_weight 0.05
            http_method_weight 0.1
            user_agent_weight 0.05
            referrer_weight 0.05
            request_frequency_weight 0.1

            # Request History Settings
            history_window 10m
            max_history_entries 2000

            # Enable ML and Model Path
            enable_ml true
            model_path pre-trained.model

             # Redaction List
            header_redaction_list Authorization Cookie Set-Cookie X-Api-Key
            query_param_redaction_list token password api_key secret

            # Dynamic Thresholds (disabled by default)
            dynamic_threshold_enabled false
            dynamic_threshold_factor 1.2

            # Normalization Configuration
            normalization_config request_size linear header_count log query_param_count linear path_segment_count log referrer linear

             # Default Per-Path Configuration
            default_path_config {
                anomaly_threshold 0.1
                blocking_threshold 0.4
            }

            # Per-Path Configurations (Using regex)
            per_path_config "^/api/v[0-9]+(/.*)?$" {  # API endpoints with versioning
                anomaly_threshold 0.1
                blocking_threshold 0.5
            }

            per_path_config "^/admin(/.*)?$" {  # Admin interface
                anomaly_threshold 0.02
                blocking_threshold 0.2
            }
             per_path_config "/download" { # Download endpoint with strict rules
                anomaly_threshold 0.3
                blocking_threshold 0.7
            }

            per_path_config "/health" { # Health endpoint, least strict, not blocked ever
                anomaly_threshold 1
                blocking_threshold 10
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
| `header_redaction_list`    | `string...` | `["Authorization", "Cookie", "Set-Cookie"]`     | List of headers to be redacted. These will be matched using regular expressions.                                                                 |
| `query_param_redaction_list`  | `string...` | `["token", "password", "api_key"]`     | List of query parameters to be redacted. These will be matched using regular expressions.                                                                 |
 | `dynamic_threshold_enabled`  | `boolean`     | `false`   | If enabled, the anomaly threshold will be calculated based on a moving average.                                                                        |
|`dynamic_threshold_factor`  | `float` | `1.0` | Factor to be applied to the moving average, only used if `dynamic_threshold_enabled` is `true`.
| `enable_ml`                | `boolean` | `false`   | If enabled, the Machine learning-based score will be added to the anomaly score.   |
| `model_path`               | `string`     | `""`    | Path to the pre-trained model file.                                                                                                               |

### Normalization Configuration

*   **`normalization_config`**: You can now configure the normalization method for specific attributes using a `normalization_config` block inside the `ml_waf` configuration.

    *   You can choose between `linear` (default value) or `log` (logarithmic) normalizations.

    ```caddyfile
    ml_waf {
         normalization_config request_size linear
         normalization_config header_count log
         normalization_config query_param_count linear
         normalization_config path_segment_count log
         normalization_config referrer linear
    }
    ```

### Per-Path Configuration

-   **`per_path_config <path> { ... }`**: Allows you to set different `anomaly_threshold` and `blocking_threshold` options for a specific path. You can use regular expressions to match multiple paths.
    -   **`anomaly_threshold`**: `float`. Overrides the global `anomaly_threshold` for this path.
    -   **`blocking_threshold`**: `float`. Overrides the global `blocking_threshold` for this path.

#### Default Path Configuration

-   **`default_path_config { ... }`**: Allows you to set default values for the per-path configuration, to be used when a path is not defined.
    -   **`anomaly_threshold`**: `float`. The anomaly_threshold to be used as the default.
    -   **`blocking_threshold`**: `float`. The blocking_threshold to be used as the default.

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
        blocking_threshold 0.2
    }

    per_path_config /sensitive-api {
        anomaly_threshold 0.2
        blocking_threshold 0.4
    }
    default_path_config {
        anomaly_threshold 0.15
        blocking_threshold 0.5
     }
}
```

**Explanation:**

-   Global thresholds are set for general protection.
-   `per_path_config` is used to apply stricter thresholds for sensitive paths like `/admin` and `/sensitive-api`.
-   `default_path_config` will be used for any other path that is not explicitly declared.

## 7. Advanced Configuration

### Admin Endpoint
The `caddy-adf` module exposes an admin endpoint that you can use to update the model and see the current configuration.
*   The `/ml_waf` path is reserved for this endpoint.

#### Update Model Endpoint

*   **URL:** `POST /ml_waf/update_model`
*   **Description:** Updates the ML model at runtime without requiring a Caddy restart.
*   **Request Body:**

    ```json
    {
      "model_path": "/path/to/your/new_pre-trained.model"
    }
    ```

*   **Response:**
    *   `200 OK`:  If successful, the response will have a `200` status code and the following JSON message:

        ```json
        {
        "message": "ML Model updated successfully"
        }
        ```
    *   `400 Bad Request`: If there's an error parsing the JSON payload or model path.

#### Get Config Endpoint

*   **URL:** `GET /ml_waf/get_config`
*   **Description:** Get the current configuration of the module.
*    **Response Body:**

    ```json
        {
            "anomaly_threshold": 0.2,
             "blocking_threshold": 0.7,
             "model_path": "pre-trained.model",
            "dynamic_threshold_enabled": false,
            "dynamic_threshold_factor": 1.2
        }
    ```

### Tuning Weights

The `caddy-adf` module uses weights to determine the contribution of different request attributes to the anomaly score. These weights allow you to customize the module's sensitivity to various aspects of incoming requests. Effective weight tuning is crucial for achieving a balance between security and usability.

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
  
 -   **Dynamic Thresholds** If you set `dynamic_threshold_enabled` to `true`, the `anomaly_threshold` will be calculated based on a moving average, using the `dynamic_threshold_factor`. For example, if the default `anomaly_threshold` is `0.4` and the `dynamic_threshold_factor` is `1.2`, and the moving average is `0.4` then, the dynamic threshold will be `0.4 * 1.2 = 0.48`.

   ```caddyfile
    ml_waf {
         dynamic_threshold_enabled true
         dynamic_threshold_factor 1.2
       # ... other options
      }
      ```
-  **Default Path Configurations:** If you don't set a per path config for some of the paths, you can configure the default values with the `default_path_config` option.

 ```caddyfile
            ml_waf {
             default_path_config {
                anomaly_threshold 0.15
                blocking_threshold 0.5
            }
        }

 ```

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

This provides detailed information about each request, the calculated anomaly scores, and any decisions made by `caddy-adf`.

### Specific Error Messages

When a request is blocked by the middleware, the response will have:

* The `403 Forbidden` HTTP status code.
* The header `X-ML-WAF-Blocked` set to `true`.
* The header `X-ML-WAF-Anomaly-Score` with the anomaly score of the request.
* A body with the error and the `anomaly score` of the request.

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

Contributions to `caddy-adf` are welcome! Please feel free to submit issues, feature requests, or pull requests.

## 10. License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
