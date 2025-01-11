package caddymlf

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(MLWAF{})
	httpcaddyfile.RegisterHandlerDirective("ml_waf", parseMLWAFCaddyfile)
}

// MLWAF implements a simulated Machine Learning WAF middleware with request correlation.
type MLWAF struct {
	AnomalyThreshold          float64       `json:"anomaly_threshold,omitempty"`
	BlockingThreshold         float64       `json:"blocking_threshold,omitempty"`
	NormalRequestSizeRangeMin int           `json:"normal_request_size_min,omitempty"`
	NormalRequestSizeRangeMax int           `json:"normal_request_size_max,omitempty"`
	NormalHeaderCountMin      int           `json:"normal_header_count_min,omitempty"`
	NormalHeaderCountMax      int           `json:"normal_header_count_max,omitempty"`
	NormalQueryParamCountMin  int           `json:"normal_query_param_count_min,omitempty"`
	NormalQueryParamCountMax  int           `json:"normal_query_param_count_max,omitempty"`
	NormalPathSegmentCountMin int           `json:"normal_path_segment_count_min,omitempty"`
	NormalPathSegmentCountMax int           `json:"normal_path_segment_count_max,omitempty"`
	RequestSizeWeight         float64       `json:"request_size_weight,omitempty"`
	HeaderCountWeight         float64       `json:"header_count_weight,omitempty"`
	QueryParamCountWeight     float64       `json:"query_param_count_weight,omitempty"`
	PathSegmentCountWeight    float64       `json:"path_segment_count_weight,omitempty"`
	HistoryWindow             time.Duration `json:"history_window,omitempty"`
	MaxHistoryEntries         int           `json:"max_history_entries,omitempty"`
	NormalHTTPMethods         []string      `json:"normal_http_methods,omitempty"` // Allowed HTTP methods
	NormalUserAgents          []string      `json:"normal_user_agents,omitempty"`  // Allowed User-Agent strings
	NormalReferrers           []string      `json:"normal_referrers,omitempty"`    // Allowed Referrer headers
	HTTPMethodWeight          float64       `json:"http_method_weight,omitempty"`  // Weight for HTTP method
	UserAgentWeight           float64       `json:"user_agent_weight,omitempty"`   // Weight for User-Agent
	ReferrerWeight            float64       `json:"referrer_weight,omitempty"`     // Weight for Referrer

	requestHistory map[string][]requestRecord
	historyMutex   sync.Mutex
	logger         *zap.Logger
}

type requestRecord struct {
	Timestamp    time.Time
	AnomalyScore float64
}

// CaddyModule returns the Caddy module information.
func (MLWAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ml_waf",
		New: func() caddy.Module { return new(MLWAF) },
	}
}

// Provision sets up the middleware.
func (m *MLWAF) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("ML WAF middleware provisioned")
	m.requestHistory = make(map[string][]requestRecord)
	return nil
}

func (m *MLWAF) Validate() error {
	// Validate thresholds
	if m.AnomalyThreshold >= m.BlockingThreshold {
		return fmt.Errorf("anomaly_threshold should be less than blocking_threshold")
	}

	// Validate weights
	if m.RequestSizeWeight < 0 {
		return fmt.Errorf("request_size_weight cannot be negative")
	}
	if m.HeaderCountWeight < 0 {
		return fmt.Errorf("header_count_weight cannot be negative")
	}
	if m.QueryParamCountWeight < 0 {
		return fmt.Errorf("query_param_count_weight cannot be negative")
	}
	if m.PathSegmentCountWeight < 0 {
		return fmt.Errorf("path_segment_count_weight cannot be negative")
	}

	// Validate ranges
	if m.NormalRequestSizeRangeMin > 0 && m.NormalRequestSizeRangeMax > 0 && m.NormalRequestSizeRangeMin >= m.NormalRequestSizeRangeMax {
		return fmt.Errorf("normal_request_size_min should be less than normal_request_size_max")
	}
	if m.NormalHeaderCountMin > 0 && m.NormalHeaderCountMax > 0 && m.NormalHeaderCountMin >= m.NormalHeaderCountMax {
		return fmt.Errorf("normal_header_count_min should be less than normal_header_count_max")
	}
	if m.NormalQueryParamCountMin > 0 && m.NormalQueryParamCountMax > 0 && m.NormalQueryParamCountMin >= m.NormalQueryParamCountMax {
		return fmt.Errorf("normal_query_param_count_min should be less than normal_query_param_count_max")
	}
	if m.NormalPathSegmentCountMin > 0 && m.NormalPathSegmentCountMax > 0 && m.NormalPathSegmentCountMin >= m.NormalPathSegmentCountMax {
		return fmt.Errorf("normal_path_segment_count_min should be less than normal_path_segment_count_max")
	}

	// Ensure ranges are valid (min and max must both be positive)
	if m.NormalRequestSizeRangeMin < 0 || m.NormalRequestSizeRangeMax < 0 {
		return fmt.Errorf("normal_request_size_range values must be positive")
	}
	if m.NormalHeaderCountMin < 0 || m.NormalHeaderCountMax < 0 {
		return fmt.Errorf("normal_header_count_range values must be positive")
	}
	if m.NormalQueryParamCountMin < 0 || m.NormalQueryParamCountMax < 0 {
		return fmt.Errorf("normal_query_param_count_range values must be positive")
	}
	if m.NormalPathSegmentCountMin < 0 || m.NormalPathSegmentCountMax < 0 {
		return fmt.Errorf("normal_path_segment_count_range values must be positive")
	}

	// Validate history configuration
	if m.HistoryWindow <= 0 {
		return fmt.Errorf("history_window must be a positive duration")
	}
	if m.MaxHistoryEntries <= 0 {
		return fmt.Errorf("max_history_entries must be a positive integer")
	}

	// Validate weights for new attributes
	if m.HTTPMethodWeight < 0 {
		return fmt.Errorf("http_method_weight cannot be negative")
	}
	if m.UserAgentWeight < 0 {
		return fmt.Errorf("user_agent_weight cannot be negative")
	}
	if m.ReferrerWeight < 0 {
		return fmt.Errorf("referrer_weight cannot be negative")
	}

	return nil
}

// Helper function to sanitize headers
func sanitizeHeaders(headers http.Header) http.Header {
	sanitized := make(http.Header)
	for key, values := range headers {
		sanitized[key] = values
	}

	// Redact sensitive headers
	sensitiveHeaders := []string{"Authorization", "Cookie", "Set-Cookie"}
	for _, h := range sensitiveHeaders {
		if sanitized.Get(h) != "" {
			sanitized.Set(h, "REDACTED")
		}
	}
	return sanitized
}

// Helper function to sanitize query parameters
func sanitizeQueryParams(queryParams url.Values) url.Values {
	sanitized := make(url.Values)
	for key, values := range queryParams {
		sanitized[key] = values
	}

	// Redact sensitive query parameters
	sensitiveParams := []string{"token", "password", "api_key"}
	for _, p := range sensitiveParams {
		if sanitized.Get(p) != "" {
			sanitized.Set(p, "REDACTED")
		}
	}
	return sanitized
}

func (m *MLWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	startTime := time.Now()
	clientIP := r.RemoteAddr

	// Handle negative request size
	requestSize := r.ContentLength
	if requestSize < 0 {
		requestSize = 0
	}

	headerCount := len(r.Header)
	queryParamCount := len(r.URL.Query())
	pathSegmentCount := len(strings.Split(strings.Trim(r.URL.Path, "/"), "/"))
	httpMethod := r.Method
	userAgent := r.Header.Get("User-Agent")
	referrer := r.Header.Get("Referer")

	// Sanitize sensitive data before logging
	sanitizedHeaders := sanitizeHeaders(r.Header)
	sanitizedQueryParams := sanitizeQueryParams(r.URL.Query())

	// Log detailed request information
	m.logger.Debug("incoming request",
		zap.String("client_ip", clientIP),
		zap.String("method", httpMethod),
		zap.String("path", r.URL.Path),
		zap.Int64("request_size", requestSize),
		zap.Int("header_count", headerCount),
		zap.Int("query_param_count", queryParamCount),
		zap.Int("path_segment_count", pathSegmentCount),
		zap.String("user_agent", userAgent),
		zap.String("referrer", referrer),
		zap.Any("headers", sanitizedHeaders),          // Log sanitized headers
		zap.Any("query_params", sanitizedQueryParams), // Log sanitized query parameters
	)

	// Fix race condition: Protect access to requestHistory
	m.historyMutex.Lock()
	history := m.requestHistory[clientIP]
	m.historyMutex.Unlock()

	// Calculate anomaly score
	anomalyScore := m.calculateAnomalyScore(requestSize, headerCount, queryParamCount, pathSegmentCount, history, httpMethod, userAgent, referrer)

	// Log anomaly score calculation details
	m.logger.Debug("calculated anomaly score",
		zap.String("client_ip", clientIP),
		zap.Float64("anomaly_score", anomalyScore),
		zap.String("path", r.URL.Path),
	)

	if anomalyScore >= m.BlockingThreshold {
		m.logger.Warn("blocking request due to high anomaly score",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
		w.WriteHeader(http.StatusForbidden)
		m.updateRequestHistory(clientIP, anomalyScore)
		return nil
	}

	if anomalyScore >= m.AnomalyThreshold {
		w.Header().Set("X-Suspicious-Traffic", "true")
		m.logger.Warn("marking traffic as suspicious",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
	}

	// Create a response writer wrapper to capture the status code
	rw := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK}
	err := next.ServeHTTP(rw, r)
	statusCode := rw.statusCode

	duration := time.Since(startTime)
	m.logger.Debug("request processed",
		zap.String("client_ip", clientIP),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", duration),
		zap.String("path", r.URL.Path),
	)

	m.updateRequestHistory(clientIP, anomalyScore)
	return err
}

// updateRequestHistory adds the current request to the history and prunes old entries.
func (m *MLWAF) updateRequestHistory(clientIP string, anomalyScore float64) {
	m.historyMutex.Lock()
	defer m.historyMutex.Unlock()

	record := requestRecord{Timestamp: time.Now(), AnomalyScore: anomalyScore}
	history := append(m.requestHistory[clientIP], record)

	// Prune old entries based on time window
	cutoff := time.Now().Add(-m.HistoryWindow)
	prunedHistory := make([]requestRecord, 0, len(history))
	for _, rec := range history {
		if rec.Timestamp.After(cutoff) {
			prunedHistory = append(prunedHistory, rec)
		}
	}

	// Prune if the number of entries exceeds the maximum
	if len(prunedHistory) > m.MaxHistoryEntries {
		prunedHistory = prunedHistory[len(prunedHistory)-m.MaxHistoryEntries:]
	}

	m.requestHistory[clientIP] = prunedHistory

	// Log request history update
	m.logger.Debug("updated request history",
		zap.String("client_ip", clientIP),
		zap.Float64("anomaly_score", anomalyScore),
		zap.Int("history_size", len(prunedHistory)),
	)
}

// responseWriterWrapper is a custom ResponseWriter to capture the status code.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (m *MLWAF) calculateAnomalyScore(requestSize int64, headerCount int, queryParamCount int, pathSegmentCount int, history []requestRecord, httpMethod string, userAgent string, referrer string) float64 {
	score := 0.0

	// Helper function to normalize
	normalize := func(value float64, min float64, max float64) float64 {
		if min == max {
			return 0.0 // No range, so no deviation
		}
		if value < min {
			return (min - value) / (min + 1) // Add 1 to avoid division by zero
		} else if value > max {
			return math.Log((value-max)/(max+1) + 1) // Logarithmic scaling for large values
		}
		return 0.0 // Within normal range
	}

	// Calculate score for request size
	if m.RequestSizeWeight > 0 {
		var normalizedRequestSize float64 = 0.0
		if m.NormalRequestSizeRangeMin > 0 && m.NormalRequestSizeRangeMax > 0 {
			normalizedRequestSize = normalize(float64(requestSize), float64(m.NormalRequestSizeRangeMin), float64(m.NormalRequestSizeRangeMax))
		}
		score += m.RequestSizeWeight * normalizedRequestSize
		m.logger.Debug("request size contribution to anomaly score",
			zap.Float64("normalized_request_size", normalizedRequestSize),
			zap.Float64("weight", m.RequestSizeWeight),
			zap.Float64("contribution", m.RequestSizeWeight*normalizedRequestSize),
		)
	}

	// Calculate score for header count
	if m.HeaderCountWeight > 0 {
		var normalizedHeaderCount float64 = 0.0
		if m.NormalHeaderCountMin > 0 && m.NormalHeaderCountMax > 0 {
			normalizedHeaderCount = normalize(float64(headerCount), float64(m.NormalHeaderCountMin), float64(m.NormalHeaderCountMax))
		}
		score += m.HeaderCountWeight * normalizedHeaderCount
		m.logger.Debug("header count contribution to anomaly score",
			zap.Float64("normalized_header_count", normalizedHeaderCount),
			zap.Float64("weight", m.HeaderCountWeight),
			zap.Float64("contribution", m.HeaderCountWeight*normalizedHeaderCount),
		)
	}

	// Calculate score for query parameter count
	if m.QueryParamCountWeight > 0 {
		var normalizedQueryParamCount float64 = 0.0
		if m.NormalQueryParamCountMin > 0 && m.NormalQueryParamCountMax > 0 {
			normalizedQueryParamCount = normalize(float64(queryParamCount), float64(m.NormalQueryParamCountMin), float64(m.NormalQueryParamCountMax))
		}
		score += m.QueryParamCountWeight * normalizedQueryParamCount
		m.logger.Debug("query parameter count contribution to anomaly score",
			zap.Float64("normalized_query_param_count", normalizedQueryParamCount),
			zap.Float64("weight", m.QueryParamCountWeight),
			zap.Float64("contribution", m.QueryParamCountWeight*normalizedQueryParamCount),
		)
	}

	// Calculate score for path segment count
	if m.PathSegmentCountWeight > 0 {
		var normalizedPathSegmentCount float64 = 0.0
		if m.NormalPathSegmentCountMin > 0 && m.NormalPathSegmentCountMax > 0 {
			normalizedPathSegmentCount = normalize(float64(pathSegmentCount), float64(m.NormalPathSegmentCountMin), float64(m.NormalPathSegmentCountMax))
		}
		score += m.PathSegmentCountWeight * normalizedPathSegmentCount
		m.logger.Debug("path segment count contribution to anomaly score",
			zap.Float64("normalized_path_segment_count", normalizedPathSegmentCount),
			zap.Float64("weight", m.PathSegmentCountWeight),
			zap.Float64("contribution", m.PathSegmentCountWeight*normalizedPathSegmentCount),
		)
	}

	// Calculate score for HTTP method
	if m.HTTPMethodWeight > 0 && len(m.NormalHTTPMethods) > 0 {
		isNormalMethod := false
		for _, method := range m.NormalHTTPMethods {
			if httpMethod == method {
				isNormalMethod = true
				break
			}
		}
		if !isNormalMethod {
			score += m.HTTPMethodWeight
			m.logger.Debug("HTTP method contribution to anomaly score",
				zap.String("http_method", httpMethod),
				zap.Float64("weight", m.HTTPMethodWeight),
				zap.Float64("contribution", m.HTTPMethodWeight),
			)
		}
	}

	// Calculate score for User-Agent
	if m.UserAgentWeight > 0 && len(m.NormalUserAgents) > 0 {
		isNormalUserAgent := false
		for _, ua := range m.NormalUserAgents {
			if strings.Contains(userAgent, ua) {
				isNormalUserAgent = true
				break
			}
		}
		if !isNormalUserAgent {
			score += m.UserAgentWeight
			m.logger.Debug("User-Agent contribution to anomaly score",
				zap.String("user_agent", userAgent),
				zap.Float64("weight", m.UserAgentWeight),
				zap.Float64("contribution", m.UserAgentWeight),
			)
		}
	}

	// Calculate score for Referrer
	if m.ReferrerWeight > 0 && len(m.NormalReferrers) > 0 {
		isNormalReferrer := false
		for _, ref := range m.NormalReferrers {
			if strings.Contains(referrer, ref) {
				isNormalReferrer = true
				break
			}
		}
		if !isNormalReferrer {
			score += m.ReferrerWeight
			m.logger.Debug("Referrer contribution to anomaly score",
				zap.String("referrer", referrer),
				zap.Float64("weight", m.ReferrerWeight),
				zap.Float64("contribution", m.ReferrerWeight),
			)
		}
	}

	// Apply correlation logic based on request history
	correlationScore := 0.0
	for _, record := range history {
		timeDiff := time.Since(record.Timestamp).Seconds()
		if record.AnomalyScore >= m.AnomalyThreshold {
			timeWeight := math.Exp(-timeDiff / 60) // decay exponentially over 60 seconds
			severityWeight := record.AnomalyScore / m.BlockingThreshold

			correlationScore += 0.15 * timeWeight * severityWeight
			m.logger.Debug("correlation score contribution from history",
				zap.Time("record_timestamp", record.Timestamp),
				zap.Float64("record_anomaly_score", record.AnomalyScore),
				zap.Float64("time_weight", timeWeight),
				zap.Float64("severity_weight", severityWeight),
				zap.Float64("contribution", 0.15*timeWeight*severityWeight),
			)
		}
	}
	score += correlationScore

	// Log total anomaly score
	m.logger.Debug("total anomaly score calculated",
		zap.Float64("total_score", score),
	)

	return score
}

// UnmarshalCaddyfile parses the Caddyfile configuration.
func (m *MLWAF) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "anomaly_threshold":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing anomaly_threshold: %v", err)
				}
				m.AnomalyThreshold = val
			case "blocking_threshold":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing blocking_threshold: %v", err)
				}
				m.BlockingThreshold = val
			case "normal_request_size_range":
				if !d.NextArg() {
					return d.ArgErr()
				}
				minValStr := d.Val()
				if !d.NextArg() {
					return d.ArgErr()
				}
				maxValStr := d.Val()

				minVal, err := strconv.Atoi(minValStr)
				if err != nil {
					return d.Errf("parsing normal_request_size_range min: %v", err)
				}
				maxVal, err := strconv.Atoi(maxValStr)
				if err != nil {
					return d.Errf("parsing normal_request_size_range max: %v", err)
				}
				m.NormalRequestSizeRangeMin = minVal
				m.NormalRequestSizeRangeMax = maxVal
			case "normal_header_count_range":
				if !d.NextArg() {
					return d.ArgErr()
				}
				minValStr := d.Val()
				if !d.NextArg() {
					return d.ArgErr()
				}
				maxValStr := d.Val()

				minVal, err := strconv.Atoi(minValStr)
				if err != nil {
					return d.Errf("parsing normal_header_count_range min: %v", err)
				}
				maxVal, err := strconv.Atoi(maxValStr)
				if err != nil {
					return d.Errf("parsing normal_header_count_range max: %v", err)
				}
				m.NormalHeaderCountMin = minVal
				m.NormalHeaderCountMax = maxVal
			case "normal_query_param_count_range":
				if !d.NextArg() {
					return d.ArgErr()
				}
				minValStr := d.Val()
				if !d.NextArg() {
					return d.ArgErr()
				}
				maxValStr := d.Val()

				minVal, err := strconv.Atoi(minValStr)
				if err != nil {
					return d.Errf("parsing normal_query_param_count_range min: %v", err)
				}
				maxVal, err := strconv.Atoi(maxValStr)
				if err != nil {
					return d.Errf("parsing normal_query_param_count_range max: %v", err)
				}
				m.NormalQueryParamCountMin = minVal
				m.NormalQueryParamCountMax = maxVal
			case "normal_path_segment_count_range":
				if !d.NextArg() {
					return d.ArgErr()
				}
				minValStr := d.Val()
				if !d.NextArg() {
					return d.ArgErr()
				}
				maxValStr := d.Val()

				minVal, err := strconv.Atoi(minValStr)
				if err != nil {
					return d.Errf("parsing normal_path_segment_count_range min: %v", err)
				}
				maxVal, err := strconv.Atoi(maxValStr)
				if err != nil {
					return d.Errf("parsing normal_path_segment_count_range max: %v", err)
				}
				m.NormalPathSegmentCountMin = minVal
				m.NormalPathSegmentCountMax = maxVal
			case "request_size_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing request_size_weight: %v", err)
				}
				m.RequestSizeWeight = val
			case "header_count_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing header_count_weight: %v", err)
				}
				m.HeaderCountWeight = val
			case "query_param_count_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing query_param_count_weight: %v", err)
				}
				m.QueryParamCountWeight = val
			case "path_segment_count_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing path_segment_count_weight: %v", err)
				}
				m.PathSegmentCountWeight = val
			case "history_window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				duration, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("parsing history_window: %v", err)
				}
				m.HistoryWindow = duration
			case "max_history_entries":
				if !d.NextArg() {
					return d.ArgErr()
				}
				count, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("parsing max_history_entries: %v", err)
				}
				m.MaxHistoryEntries = count
			case "normal_http_methods":
				m.NormalHTTPMethods = []string{}
				for d.NextArg() {
					m.NormalHTTPMethods = append(m.NormalHTTPMethods, d.Val())
				}
			case "normal_user_agents":
				m.NormalUserAgents = []string{}
				for d.NextArg() {
					m.NormalUserAgents = append(m.NormalUserAgents, d.Val())
				}
			case "normal_referrers":
				m.NormalReferrers = []string{}
				for d.NextArg() {
					m.NormalReferrers = append(m.NormalReferrers, d.Val())
				}
			case "http_method_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing http_method_weight: %v", err)
				}
				m.HTTPMethodWeight = val
			case "user_agent_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing user_agent_weight: %v", err)
				}
				m.UserAgentWeight = val
			case "referrer_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing referrer_weight: %v", err)
				}
				m.ReferrerWeight = val
			default:
				return d.Errf("unrecognized option: %s", d.Val())
			}
		}
	}
	return nil
}

// parseMLWAFCaddyfile parses the Caddyfile directive.
func parseMLWAFCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := MLWAF{
		RequestSizeWeight:      1.0, // Default weights
		HeaderCountWeight:      1.0,
		QueryParamCountWeight:  1.0,
		PathSegmentCountWeight: 1.0,
		HistoryWindow:          1 * time.Minute, // Default history window
		MaxHistoryEntries:      10,              // Default max history entries
	}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*MLWAF)(nil)
	_ caddy.Validator             = (*MLWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*MLWAF)(nil)
	_ caddyfile.Unmarshaler       = (*MLWAF)(nil)
)
