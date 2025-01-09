# Caddy ML WAF (caddy-mlf)

[![Go Reference](https://pkg.go.dev/badge/github.com/yourusername/caddy-mlf)](https://pkg.go.dev/github.com/yourusername/caddy-mlf)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Caddy module implementing a simulated Machine Learning Web Application Firewall (WAF) with request correlation. This module analyzes incoming HTTP requests based on various characteristics and calculates an anomaly score. Based on configurable thresholds, it can mark requests as suspicious or block them entirely.

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
    *   [`request_size_weight`](#request_size_weight)
    *   [`header_count_weight`](#header_count_weight)
    *   [`query_param_count_weight`](#query_param_count_weight)
    *   [`path_segment_count_weight`](#path_segment_count_weight)
    *   [`history_window`](#history_window)
    *   [`max_history_entries`](#max_history_entries)
*   [How It Works](#how-it-works)
*   [Contributing](#contributing)
*   [License](#license)

## Introduction

The `caddy-mlf` module provides a simulated Machine Learning WAF functionality within the Caddy web server. It aims to detect potentially malicious requests by analyzing request attributes like size, header count, query parameters, and path segments. It also incorporates a basic request correlation mechanism by considering the recent request history from the same client IP.

**Disclaimer:** This module is a *simulation* and does not implement actual machine learning models. It relies on configurable thresholds and weights to determine anomaly scores. It should not be used in production environments where robust security is critical.

## Installation

To install the `caddy-mlf` module, you'll need to build Caddy with this module included.

1. **Install xcaddy:** If you don't have it already, install xcaddy:
    ```bash
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    ```

2. **Build Caddy with the module:** Navigate to where you want to build Caddy and run:
    ```bash
    xcaddy build --with github.com/fabriziosalmi/caddy-mlf
    ```
    *(Replace `github.com/fabriziosalmi/caddy-mlf` with the actual import path of your module.)*

   This will create an executable named `caddy` in your current directory.

## Usage

To use the `caddy-mlf` module, you need to configure it within your Caddyfile. The directive for this module is `ml_waf`.

### Basic Configuration

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
            anomaly_threshold 0.7                  # Anomaly score above which traffic is marked as suspicious
            blocking_threshold 0.95                # Anomaly score above which traffic is blocked
            normal_request_size_range 50 2000      # Min and max size (in bytes) of a normal request
            normal_header_count_range 3 30         # Min and max number of headers in a normal request
            normal_query_param_count_range 0 10    # Min and max number of query parameters in a normal request
            normal_path_segment_count_range 1 5    # Min and max number of path segments in a normal request
            request_size_weight 0.4                # Weight given to deviations in request size
            header_count_weight 0.3                # Weight given to deviations in header count
            query_param_count_weight 0.2           # Weight given to deviations in query parameter count
            path_segment_count_weight 0.1          # Weight given to deviations in path segment count
            history_window 10m                     # Time window for considering past requests (e.g., 5m, 1h)
            max_history_entries 30                 # Maximum number of past requests to keep in history
        }
        respond "Hello, world!"
    }
}
```

This basic configuration enables the `ml_waf` module with default weights and history settings. Requests with an anomaly score of 0.5 or higher will be marked as suspicious, and those with 0.8 or higher will be blocked.

### Available Options

The `ml_waf` directive accepts the following options within its block:

*   [`anomaly_threshold`](#anomaly_threshold)
*   [`blocking_threshold`](#blocking_threshold)
*   [`normal_request_size_range`](#normal_request_size_range)
*   [`normal_header_count_range`](#normal_header_count_range)
*   [`normal_query_param_count_range`](#normal_query_param_count_range)
*   [`normal_path_segment_count_range`](#normal_path_segment_count_range)
*   [`request_size_weight`](#request_size_weight)
*   [`header_count_weight`](#header_count_weight)
*   [`query_param_count_weight`](#query_param_count_weight)
*   [`path_segment_count_weight`](#path_segment_count_weight)
*   [`history_window`](#history_window)
*   [`max_history_entries`](#max_history_entries)

## Configuration Options Details

This section provides detailed information about each available option for the `ml_waf` directive.

### `anomaly_threshold`

*   **Description:**  Sets the threshold for considering a request potentially anomalous. If the calculated anomaly score is greater than or equal to this value, the `X-Suspicious-Traffic` header will be added to the response.
*   **Data Type:** `float`
*   **Default:** None (must be configured)
*   **Example:**
    ```caddyfile
    ml_waf {
        anomaly_threshold 0.6
    }
    ```

### `blocking_threshold`

*   **Description:** Sets the threshold for blocking a request. If the calculated anomaly score is greater than or equal to this value, the request will be blocked with a 403 Forbidden response.
*   **Data Type:** `float`
*   **Default:** None (must be configured)
*   **Example:**
    ```caddyfile
    ml_waf {
        blocking_threshold 0.9
    }
    ```

### `normal_request_size_range`

*   **Description:** Defines the expected range (minimum and maximum, in bytes) for normal request sizes. Requests outside this range will contribute to the anomaly score.
*   **Data Type:** `integer` (minimum) `integer` (maximum)
*   **Default:** None
*   **Example:**
    ```caddyfile
    ml_waf {
        normal_request_size_range 100 1000
    }
    ```

### `normal_header_count_range`

*   **Description:** Defines the expected range (minimum and maximum) for the number of headers in a normal request. Requests with a header count outside this range will contribute to the anomaly score.
*   **Data Type:** `integer` (minimum) `integer` (maximum)
*   **Default:** None
*   **Example:**
    ```caddyfile
    ml_waf {
        normal_header_count_range 5 20
    }
    ```

### `normal_query_param_count_range`

*   **Description:** Defines the expected range (minimum and maximum) for the number of query parameters in a normal request. Requests with a query parameter count outside this range will contribute to the anomaly score.
*   **Data Type:** `integer` (minimum) `integer` (maximum)
*   **Default:** None
*   **Example:**
    ```caddyfile
    ml_waf {
        normal_query_param_count_range 0 5
    }
    ```

### `normal_path_segment_count_range`

*   **Description:** Defines the expected range (minimum and maximum) for the number of path segments in the request URL. Requests with a path segment count outside this range will contribute to the anomaly score.
*   **Data Type:** `integer` (minimum) `integer` (maximum)
*   **Default:** None
*   **Example:**
    ```caddyfile
    ml_waf {
        normal_path_segment_count_range 1 3
    }
    ```

### `request_size_weight`

*   **Description:** Determines the weight or importance of the request size deviation in the overall anomaly score calculation. A higher weight means deviations in request size have a greater impact on the score.
*   **Data Type:** `float`
*   **Default:** `1.0`
*   **Example:**
    ```caddyfile
    ml_waf {
        request_size_weight 0.8
    }
    ```

### `header_count_weight`

*   **Description:** Determines the weight or importance of the header count deviation in the overall anomaly score calculation.
*   **Data Type:** `float`
*   **Default:** `1.0`
*   **Example:**
    ```caddyfile
    ml_waf {
        header_count_weight 0.7
    }
    ```

### `query_param_count_weight`

*   **Description:** Determines the weight or importance of the query parameter count deviation in the overall anomaly score calculation.
*   **Data Type:** `float`
*   **Default:** `1.0`
*   **Example:**
    ```caddyfile
    ml_waf {
        query_param_count_weight 0.6
    }
    ```

### `path_segment_count_weight`

*   **Description:** Determines the weight or importance of the path segment count deviation in the overall anomaly score calculation.
*   **Data Type:** `float`
*   **Default:** `1.0`
*   **Example:**
    ```caddyfile
    ml_waf {
        path_segment_count_weight 0.5
    }
    ```

### `history_window`

*   **Description:** Specifies the time duration for which request history is maintained for each client IP. This history is used to correlate subsequent requests and potentially increase their anomaly score if previous requests were suspicious.
*   **Data Type:** `duration` (e.g., `1m`, `30s`, `5h`)
*   **Default:** `1m`
*   **Example:**
    ```caddyfile
    ml_waf {
        history_window 5m
    }
    ```

### `max_history_entries`

*   **Description:** Sets the maximum number of recent requests to store in the history for each client IP.
*   **Data Type:** `integer`
*   **Default:** `10`
*   **Example:**
    ```caddyfile
    ml_waf {
        max_history_entries 20
    }
    ```

## How It Works

The `caddy-mlf` module operates as follows:

1. For each incoming request, it extracts the following attributes:
    *   Request size
    *   Number of headers
    *   Number of query parameters
    *   Number of path segments
2. It compares these attributes against the configured `normal_*` ranges. Deviations from these ranges contribute to a base anomaly score, weighted by the corresponding `*_weight` values.
3. It retrieves the recent request history for the client IP based on the `history_window` and `max_history_entries` settings.
4. If previous requests from the same client IP were marked as suspicious (anomaly score above `anomaly_threshold`), the current request's anomaly score is further increased.
5. The final anomaly score is compared against the `anomaly_threshold` and `blocking_threshold`.
6. If the score meets or exceeds the `blocking_threshold`, the request is blocked.
7. If the score meets or exceeds the `anomaly_threshold` but is below the `blocking_threshold`, the `X-Suspicious-Traffic: true` header is added to the response.
8. The request is then passed to the next handler in the Caddy middleware chain.

## Contributing

Contributions to the `caddy-mlf` module are welcome! Please feel free to submit bug reports, feature requests, or pull requests through the project's repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
