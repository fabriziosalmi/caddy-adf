# Caddy ML WAF (caddy-mlf)

[![Go](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml/badge.svg)](https://github.com/fabriziosalmi/caddy-mlf/actions/workflows/go.yml)

A Caddy module implementing a simulated Machine Learning Web Application Firewall (WAF) with request correlation. This module analyzes incoming HTTP requests based on various characteristics and calculates an anomaly score. Based on configurable thresholds, it can mark requests as suspicious or block them entirely. This module is designed to provide a highly customizable and flexible framework for analyzing web traffic and identifying potential threats in a simulated machine learning environment. By focusing on providing granular control and dynamic behavior, it can adapt to varying web application scenarios and requirements.

**Index**

*   [Introduction](#introduction)
*   [Installation](#installation)
*   [Usage](#usage)
    *   [Basic Configuration](#basic-configuration)
    *   [Available Options](#available-options)
*   [Configuration Options Details](#configuration-options-details)
    *   [`anomaly_threshold`](#anomaly_threshold)
    *   [`blocking_threshold`](#blocking_threshold)
    *   [`normal_request_size_range`](#normal_request_size_range)
    *   [`normal_header_count_range`](#normal_header_count_range)
    *   [`normal_query_param_count_range`](#normal_query_param_count_range)
    *   [`normal_path_segment_count_range`](#normal_path_segment_count_range)
    *   [`normal_http_methods`](#normal_http_methods)
    *   [`normal_user_agents`](#normal_user_agents)
    *   [`normal_referrers`](#normal_referrers)
    *   [`request_size_weight`](#request_size_weight)
    *   [`header_count_weight`](#header_count_weight)
    *   [`query_param_count_weight`](#query_param_count_weight)
    *   [`path_segment_count_weight`](#path_segment_count_weight)
    *   [`http_method_weight`](#http_method_weight)
    *   [`user_agent_weight`](#user_agent_weight)
    *   [`referrer_weight`](#referrer_weight)
    *   [`history_window`](#history_window)
    *   [`max_history_entries`](#max_history_entries)
*   [How It Works](#how-it-works)
*   [Contributing](#contributing)
*   [License](#license)

## Introduction

The `caddy-mlf` module provides a simulated Machine Learning WAF functionality within the Caddy web server. It aims to detect potentially malicious requests by analyzing request attributes like size, header count, query parameters, and path segments. It also incorporates a basic request correlation mechanism by considering the recent request history from the same client IP.

This module is particularly useful for developers and administrators who need a lightweight and highly configurable WAF solution. By using user-defined ranges and weights, `caddy-mlf` enables fine-tuned control over how requests are evaluated, providing an effective way to simulate and study web application security mechanisms. Moreover, its ability to dynamically adapt to custom scenarios allows it to serve as an educational tool for understanding how web application firewalls function in practice.

**Disclaimer:** This module is a *simulation* and does not implement actual machine learning models. It relies on configurable thresholds and weights to determine anomaly scores. It should not be used in production environments where robust security is critical. Instead, it is a powerful tool for testing, research, and learning purposes. Whether you are experimenting with traffic patterns or analyzing common attack vectors, this module offers insights into traffic anomaly analysis.

## Installation

To install the `caddy-mlf` module, you'll need to build Caddy with this module included. The following steps outline the process for setting up and using the module in your environment.

1. **Install xcaddy:** This utility allows you to build custom versions of Caddy with additional modules.
    ```bash
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    ```

2. **Build Caddy with the module:** Use the `xcaddy` tool to build a custom Caddy binary that includes the `caddy-mlf` module.
    ```bash
    xcaddy build --with github.com/yourusername/caddy-mlf
    ```

   This will create an executable named `caddy` in your current directory. Ensure that the executable has the necessary permissions to be executed in your environment.

3. **Verify installation:** Run the custom `caddy` binary and check that the `ml_waf` module is available by listing the installed modules.

## Usage

To use the `caddy-mlf` module, you need to configure it within your Caddyfile. The directive for this module is `ml_waf`. By including this directive in your server configuration, you can activate and customize the behavior of the WAF based on your specific needs.

### Basic Configuration

The basic configuration example below demonstrates how to set up the module with common settings. This configuration can be adapted to suit the requirements of different environments and applications. It provides a starting point for experimenting with thresholds and weights to achieve the desired level of security.

```caddyfile
{
    admin off
    order ml_waf before respond
    log {
        level debug
    }
}

:8080 {
    handle {
        ml_waf {
            # Thresholds
            anomaly_threshold 0.8                  # Anomaly score above which traffic is marked as suspicious
            blocking_threshold 0.95                # Anomaly score above which traffic is blocked

            # Normal ranges for request attributes
            normal_request_size_range 50 2000      # Min and max size (in bytes) of a normal request
            normal_header_count_range 3 30         # Min and max number of headers in a normal request
            normal_query_param_count_range 0 10    # Min and max number of query parameters in a normal request
            normal_path_segment_count_range 1 5    # Min and max number of path segments in a normal request

            # Additional attributes
            normal_http_methods GET POST           # Allowed HTTP methods (e.g., GET, POST)
            normal_user_agents Chrome Firefox      # Allowed User-Agent strings (e.g., Chrome, Firefox)
            normal_referrers https://example.com   # Allowed Referrer headers (e.g., trusted domains)

            # Weights (sum = 1)
            request_size_weight 0.3          # Most critical - large or tiny requests often indicate anomalies
            header_count_weight 0.25         # Highly significant - unusual header counts are suspicious
            query_param_count_weight 0.15    # Moderate - unusual query parameters can be indicative
            http_method_weight 0.1           # Important - unusual HTTP methods could be malicious
            user_agent_weight 0.1            # Important - bots or malicious actors often have abnormal User-Agents
            referrer_weight 0.05             # Less significant - deviations may be less impactful
            path_segment_count_weight 0.05   # Less significant - anomalies here are rarer


            # Request history settings
            history_window 10m                     # Time window for considering past requests (e.g., 5m, 1h)
            max_history_entries 100                # Maximum number of past requests to keep in history
        }
        respond "Hello, world!"
    }
}
```

This configuration defines thresholds for marking and blocking requests, sets normal ranges for various attributes, and specifies weights for calculating anomaly scores. It also includes settings for request history, which are essential for correlating and analyzing patterns in client behavior. The flexibility of these parameters allows users to simulate various attack scenarios and response strategies.

### Available Options

The `ml_waf` directive accepts the following options within its block. Each option is fully customizable and allows for fine-grained control over how the WAF evaluates incoming requests. By adjusting these options, you can tailor the behavior of the module to match your specific security requirements and application context.

*   [`anomaly_threshold`](#anomaly_threshold)
*   [`blocking_threshold`](#blocking_threshold)
*   [`normal_request_size_range`](#normal_request_size_range)
*   [`normal_header_count_range`](#normal_header_count_range)
*   [`normal_query_param_count_range`](#normal_query_param_count_range)
*   [`normal_path_segment_count_range`](#normal_path_segment_count_range)
*   [`normal_http_methods`](#normal_http_methods)
*   [`normal_user_agents`](#normal_user_agents)
*   [`normal_referrers`](#normal_referrers)
*   [`request_size_weight`](#request_size_weight)
*   [`header_count_weight`](#header_count_weight)
*   [`query_param_count_weight`](#query_param_count_weight)
*   [`path_segment_count_weight`](#path_segment_count_weight)
*   [`http_method_weight`](#http_method_weight)
*   [`user_agent_weight`](#user_agent_weight)
*   [`referrer_weight`](#referrer_weight)
*   [`history_window`](#history_window)
*   [`max_history_entries`](#max_history_entries)

## Configuration Options Details

Here is the detailed configuration for the specified options:

---

### `anomaly_threshold`
* **Description:** Sets the threshold for considering a request potentially anomalous. If the calculated anomaly score equals or exceeds this value, the request is flagged as suspicious and additional actions might be triggered, such as logging or tagging the request.
* **Data Type:** `float`
* **Default:** None (must be explicitly set)
* **Example:**
    ```caddyfile
    ml_waf {
        anomaly_threshold 0.7
    }
    ```

### `blocking_threshold`
* **Description:** Defines the score at which a request is outright blocked. If a request's anomaly score equals or exceeds this value, it will be terminated with a 403 Forbidden response.
* **Data Type:** `float`
* **Default:** None (must be explicitly set)
* **Example:**
    ```caddyfile
    ml_waf {
        blocking_threshold 0.9
    }
    ```

### `normal_request_size_range`
* **Description:** Specifies the expected range for normal request sizes (in bytes). Requests outside this range contribute to the anomaly score.
* **Data Type:** `integer` (minimum), `integer` (maximum)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        normal_request_size_range 100 2000
    }
    ```

### `normal_header_count_range`
* **Description:** Sets the expected range for the number of headers in a request. Requests with fewer or more headers than the specified range contribute to the anomaly score.
* **Data Type:** `integer` (minimum), `integer` (maximum)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        normal_header_count_range 5 25
    }
    ```

### `normal_query_param_count_range`
* **Description:** Defines the expected number of query parameters in a URL. Deviations from this range affect the anomaly score.
* **Data Type:** `integer` (minimum), `integer` (maximum)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        normal_query_param_count_range 0 8
    }
    ```

### `normal_path_segment_count_range`
* **Description:** Specifies the normal range for the number of segments in a request path. Paths with fewer or more segments than this range contribute to the anomaly score.
* **Data Type:** `integer` (minimum), `integer` (maximum)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        normal_path_segment_count_range 2 5
    }
    ```

### `normal_http_methods`
* **Description:** Specifies the list of allowed HTTP methods. Requests using other methods contribute to the anomaly score.
* **Data Type:** `string` (space-separated list)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        normal_http_methods GET POST
    }
    ```

### `normal_user_agents`
* **Description:** Lists allowed User-Agent strings. Requests with unrecognized User-Agent headers contribute to the anomaly score.
* **Data Type:** `string` (space-separated list)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        normal_user_agents Chrome Firefox Safari
    }
    ```

### `normal_referrers`
* **Description:** Specifies allowed Referrer headers. Requests originating from other referrers contribute to the anomaly score.
* **Data Type:** `string` (space-separated list)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        normal_referrers https://trustedsite.com
    }
    ```

### `request_size_weight`
* **Description:** Assigns a weight to request size deviations when calculating the anomaly score. Higher weights increase the impact of this attribute on the overall score.
* **Data Type:** `float`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        request_size_weight 0.5
    }
    ```

### `header_count_weight`
* **Description:** Specifies the weight for deviations in the number of headers. This weight determines how significantly header count affects the anomaly score.
* **Data Type:** `float`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        header_count_weight 0.4
    }
    ```

### `query_param_count_weight`
* **Description:** Assigns a weight to the number of query parameters in anomaly score calculations. Higher weights emphasize the importance of this attribute.
* **Data Type:** `float`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        query_param_count_weight 0.3
    }
    ```

### `path_segment_count_weight`
* **Description:** Defines the weight for path segment count deviations. Requests with unexpected path segment counts influence the anomaly score based on this weight.
* **Data Type:** `float`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        path_segment_count_weight 0.2
    }
    ```

### `http_method_weight`
* **Description:** Specifies the weight for deviations in HTTP method usage. Higher values amplify the impact of unexpected methods on the anomaly score.
* **Data Type:** `float`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        http_method_weight 0.3
    }
    ```

### `user_agent_weight`
* **Description:** Sets the weight for deviations in User-Agent headers. This weight affects how much unrecognized User-Agent values influence the anomaly score.
* **Data Type:** `float`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        user_agent_weight 0.3
    }
    ```

### `referrer_weight`
* **Description:** Defines the weight for deviations in Referrer headers. Higher weights make mismatches more impactful on the anomaly score.
* **Data Type:** `float`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        referrer_weight 0.3
    }
    ```

### `history_window`
* **Description:** Specifies the duration of the request history considered for anomaly detection. Past requests within this window affect anomaly score calculations.
* **Data Type:** `duration` (e.g., `1m`, `10m`, `1h`)
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        history_window 5m
    }
    ```

### `max_history_entries`
* **Description:** Sets the maximum number of requests to retain in the history for each client. Older entries are removed as new ones are added.
* **Data Type:** `integer`
* **Default:** None
* **Example:**
    ```caddyfile
    ml_waf {
        max_history_entries 50
    }
    ```
    
## How It Works

The `caddy-mlf` module operates as follows:

1. Extracts attributes from each incoming request, such as request size, header count, and more.
2. Compares these attributes to configured normal ranges and calculates an anomaly score using the specified weights.
3. Retrieves recent request history for the client IP, leveraging historical data to adjust the anomaly score based on past behavior.
4. Takes action based on the final score:
   * If the score meets or exceeds the `blocking_threshold`, the request is blocked.
   * If the score is above the `anomaly_threshold` but below the `blocking_threshold`, the request is marked as suspicious by adding a `X-Suspicious-Traffic` header.
5. Allows non-suspicious requests to proceed to the next middleware or handler in the chain.

This flow ensures that requests are evaluated in real-time, with decisions based on both individual attributes and contextual patterns from recent activity. By maintaining a history of request patterns, the module is able to detect evolving threats and react dynamically to anomalous behavior.

## Contributing

Contributions to the `caddy-mlf` module are welcome! Whether you're reporting a bug, suggesting an enhancement, or submitting a pull request, your input is valuable. Please follow the contribution guidelines outlined in the repository and ensure that your changes align with the project's goals. We encourage contributions that enhance the module's functionality, improve its performance, or expand its educational value.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

