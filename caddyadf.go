package caddyadf

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
	AnomalyThreshold          float64               `json:"anomaly_threshold,omitempty"`
	BlockingThreshold         float64               `json:"blocking_threshold,omitempty"`
	NormalRequestSizeRangeMin int                   `json:"normal_request_size_min,omitempty"`
	NormalRequestSizeRangeMax int                   `json:"normal_request_size_max,omitempty"`
	NormalHeaderCountMin      int                   `json:"normal_header_count_min,omitempty"`
	NormalHeaderCountMax      int                   `json:"normal_header_count_max,omitempty"`
	NormalQueryParamCountMin  int                   `json:"normal_query_param_count_min,omitempty"`
	NormalQueryParamCountMax  int                   `json:"normal_query_param_count_max,omitempty"`
	NormalPathSegmentCountMin int                   `json:"normal_path_segment_count_min,omitempty"`
	NormalPathSegmentCountMax int                   `json:"normal_path_segment_count_max,omitempty"`
	RequestSizeWeight         float64               `json:"request_size_weight,omitempty"`
	HeaderCountWeight         float64               `json:"header_count_weight,omitempty"`
	QueryParamCountWeight     float64               `json:"query_param_count_weight,omitempty"`
	PathSegmentCountWeight    float64               `json:"path_segment_count_weight,omitempty"`
	RequestFrequencyWeight    float64               `json:"request_frequency_weight,omitempty"`
	HistoryWindow             time.Duration         `json:"history_window,omitempty"`
	MaxHistoryEntries         int                   `json:"max_history_entries,omitempty"`
	NormalHTTPMethods         []string              `json:"normal_http_methods,omitempty"`
	NormalUserAgents          []string              `json:"normal_user_agents,omitempty"`
	NormalReferrers           []string              `json:"normal_referrers,omitempty"`
	HTTPMethodWeight          float64               `json:"http_method_weight,omitempty"`
	UserAgentWeight           float64               `json:"user_agent_weight,omitempty"`
	ReferrerWeight            float64               `json:"referrer_weight,omitempty"`
	PerPathConfig             map[string]PathConfig `json:"per_path_config,omitempty"`

	requestHistoryShards map[string]map[string][]requestRecord // Sharded request history by client IP and shard
	historyMutex         sync.RWMutex                          // Changed to sync.RWMutex
	numShards            int

	logger *zap.Logger
}

// PathConfig defines per-path configuration for thresholds and rules.
type PathConfig struct {
	AnomalyThreshold  float64 `json:"anomaly_threshold,omitempty"`
	BlockingThreshold float64 `json:"blocking_threshold,omitempty"`
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

// responseWriterWrapper is a custom ResponseWriter to capture the status code.
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWrapper) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (m *MLWAF) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.logger.Info("ML WAF middleware provisioned")
	m.logger.Info("using default configurations",
		zap.Float64("anomaly_threshold", m.AnomalyThreshold),
		zap.Float64("blocking_threshold", m.BlockingThreshold),
		zap.Int("normal_request_size_min", m.NormalRequestSizeRangeMin),
		zap.Int("normal_request_size_max", m.NormalRequestSizeRangeMax),
		zap.Int("normal_header_count_min", m.NormalHeaderCountMin),
		zap.Int("normal_header_count_max", m.NormalHeaderCountMax),
		zap.Int("normal_query_param_count_min", m.NormalQueryParamCountMin),
		zap.Int("normal_query_param_count_max", m.NormalQueryParamCountMax),
		zap.Int("normal_path_segment_count_min", m.NormalPathSegmentCountMin),
		zap.Int("normal_path_segment_count_max", m.NormalPathSegmentCountMax),
		zap.Float64("request_size_weight", m.RequestSizeWeight),
		zap.Float64("header_count_weight", m.HeaderCountWeight),
		zap.Float64("query_param_count_weight", m.QueryParamCountWeight),
		zap.Float64("path_segment_count_weight", m.PathSegmentCountWeight),
		zap.Float64("request_frequency_weight", m.RequestFrequencyWeight),
		zap.Float64("http_method_weight", m.HTTPMethodWeight),
		zap.Float64("user_agent_weight", m.UserAgentWeight),
		zap.Float64("referrer_weight", m.ReferrerWeight),
		zap.Duration("history_window", m.HistoryWindow),
		zap.Int("max_history_entries", m.MaxHistoryEntries),
	)

	m.numShards = 32 // Initialize with a reasonable number of shards
	m.requestHistoryShards = make(map[string]map[string][]requestRecord)
	return nil
}

func (m *MLWAF) Validate() error {
	if m.AnomalyThreshold >= m.BlockingThreshold {
		return fmt.Errorf("anomaly_threshold should be less than blocking_threshold")
	}

	if err := m.validateWeight(m.RequestSizeWeight, "request_size_weight"); err != nil {
		return err
	}
	if err := m.validateWeight(m.HeaderCountWeight, "header_count_weight"); err != nil {
		return err
	}
	if err := m.validateWeight(m.QueryParamCountWeight, "query_param_count_weight"); err != nil {
		return err
	}
	if err := m.validateWeight(m.PathSegmentCountWeight, "path_segment_count_weight"); err != nil {
		return err
	}
	if err := m.validateWeight(m.RequestFrequencyWeight, "request_frequency_weight"); err != nil {
		return err
	}
	if err := m.validateWeight(m.HTTPMethodWeight, "http_method_weight"); err != nil {
		return err
	}
	if err := m.validateWeight(m.UserAgentWeight, "user_agent_weight"); err != nil {
		return err
	}
	if err := m.validateWeight(m.ReferrerWeight, "referrer_weight"); err != nil {
		return err
	}

	if err := m.validateRange(m.NormalRequestSizeRangeMin, m.NormalRequestSizeRangeMax, "normal_request_size"); err != nil {
		return err
	}
	if err := m.validateRange(m.NormalHeaderCountMin, m.NormalHeaderCountMax, "normal_header_count"); err != nil {
		return err
	}
	if err := m.validateRange(m.NormalQueryParamCountMin, m.NormalQueryParamCountMax, "normal_query_param_count"); err != nil {
		return err
	}
	if err := m.validateRange(m.NormalPathSegmentCountMin, m.NormalPathSegmentCountMax, "normal_path_segment_count"); err != nil {
		return err
	}

	if m.HistoryWindow <= 0 {
		return fmt.Errorf("history_window must be a positive duration")
	}

	if m.MaxHistoryEntries <= 0 {
		return fmt.Errorf("max_history_entries must be a positive integer")
	}

	// Validate per-path configurations
	for path, config := range m.PerPathConfig {
		if config.AnomalyThreshold >= config.BlockingThreshold {
			return fmt.Errorf("per-path anomaly_threshold should be less than blocking_threshold for path: %s", path)
		}
	}

	return nil
}

func (m *MLWAF) validateWeight(weight float64, name string) error {
	if weight < 0 {
		return fmt.Errorf("%s cannot be negative", name)
	}
	return nil
}

func (m *MLWAF) validateRange(min int, max int, name string) error {
	if min < 0 || max < 0 {
		return fmt.Errorf("%s_range values must be positive", name)
	}
	if min > 0 && max > 0 && min >= max {
		return fmt.Errorf("%s_min should be less than %s_max", name, name)
	}

	return nil
}

// sanitizeHeaders creates a sanitized copy of the headers, redacting sensitive ones
func (m *MLWAF) sanitizeHeaders(headers http.Header) http.Header {
	sanitized := make(http.Header)
	for key, values := range headers {
		if key == "Authorization" || key == "Cookie" || key == "Set-Cookie" {
			sanitized[key] = []string{"REDACTED"}
		} else {
			sanitized[key] = values
		}
	}
	return sanitized
}

func (m *MLWAF) sanitizeQueryParams(queryParams url.Values) url.Values {
	sanitized := make(url.Values)
	for key, values := range queryParams {
		if key == "token" || key == "password" || key == "api_key" {
			sanitized[key] = []string{"REDACTED"}
		} else {
			sanitized[key] = values
		}

	}
	return sanitized
}

// getShard returns the shard number for a given client IP
func (m *MLWAF) getShard(clientIP string) string {
	hash := 0
	for _, char := range clientIP {
		hash = (hash*31 + int(char)) % m.numShards
	}
	return fmt.Sprintf("shard-%d", hash)
}

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
			case "request_frequency_weight":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing request_frequency_weight: %v", err)
				}
				m.RequestFrequencyWeight = val
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
			case "per_path_config":
				if !d.NextArg() {
					return d.ArgErr()
				}
				path := d.Val()
				config := PathConfig{}
				for d.NextBlock(1) {
					switch d.Val() {
					case "anomaly_threshold":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val, err := strconv.ParseFloat(d.Val(), 64)
						if err != nil {
							return d.Errf("parsing anomaly_threshold for path %s: %v", path, err)
						}
						config.AnomalyThreshold = val
					case "blocking_threshold":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val, err := strconv.ParseFloat(d.Val(), 64)
						if err != nil {
							return d.Errf("parsing blocking_threshold for path %s: %v", path, err)
						}
						config.BlockingThreshold = val
					default:
						return d.Errf("unrecognized option for per_path_config: %s", d.Val())
					}
				}
				if m.PerPathConfig == nil {
					m.PerPathConfig = make(map[string]PathConfig)
				}
				m.PerPathConfig[path] = config

			default:
				return d.Errf("unrecognized option: %s", d.Val())
			}
		}
	}
	return nil
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (m *MLWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	startTime := time.Now()
	clientIP := r.RemoteAddr
	shard := m.getShard(clientIP)

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
	sanitizedHeaders := m.sanitizeHeaders(r.Header)
	sanitizedQueryParams := m.sanitizeQueryParams(r.URL.Query())

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
		zap.Any("headers", sanitizedHeaders),
		zap.Any("query_params", sanitizedQueryParams),
	)

	history := m.getRequestHistory(clientIP, shard)

	anomalyScore := m.calculateAnomalyScore(requestSize, headerCount, queryParamCount, pathSegmentCount, history, httpMethod, userAgent, referrer)

	m.logger.Debug("calculated anomaly score",
		zap.String("client_ip", clientIP),
		zap.Float64("anomaly_score", anomalyScore),
		zap.String("path", r.URL.Path),
	)

	// Block or mark as suspicious based on path configuration
	pathConfig, ok := m.PerPathConfig[r.URL.Path]
	if ok {
		if err := m.handlePerPathRequest(w, clientIP, r, anomalyScore, pathConfig); err != nil {
			return err // return if there was an error.
		}
	} else {
		if err := m.handleGlobalRequest(w, clientIP, r, anomalyScore); err != nil {
			return err // return if there was an error
		}
	}

	rw := &responseWriterWrapper{ResponseWriter: w, statusCode: http.StatusOK} // Initialize responseWriterWrapper
	err := next.ServeHTTP(rw, r)
	statusCode := rw.statusCode

	duration := time.Since(startTime)
	m.logger.Debug("request processed",
		zap.String("client_ip", clientIP),
		zap.Int("status_code", statusCode),
		zap.Duration("duration", duration),
		zap.String("path", r.URL.Path),
	)

	m.updateRequestHistory(clientIP, shard, anomalyScore)

	return err
}

// handlePerPathRequest handles requests based on per-path configuration
func (m *MLWAF) handlePerPathRequest(w http.ResponseWriter, clientIP string, r *http.Request, anomalyScore float64, pathConfig PathConfig) error {
	m.logger.Debug("using per-path thresholds",
		zap.String("path", r.URL.Path),
		zap.Float64("anomaly_threshold", pathConfig.AnomalyThreshold),
		zap.Float64("blocking_threshold", pathConfig.BlockingThreshold),
	)

	if anomalyScore >= pathConfig.BlockingThreshold {
		m.logger.Warn("blocking request due to high anomaly score",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
		w.WriteHeader(http.StatusForbidden)
		return fmt.Errorf("request blocked due to high anomaly score for path: %s", r.URL.Path) // return error
	}

	if anomalyScore >= pathConfig.AnomalyThreshold {
		w.Header().Set("X-Suspicious-Traffic", "true")
		m.logger.Warn("marking traffic as suspicious",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
	}

	return nil
}

// handleGlobalRequest handles requests based on global configuration
func (m *MLWAF) handleGlobalRequest(w http.ResponseWriter, clientIP string, r *http.Request, anomalyScore float64) error {
	m.logger.Debug("using global thresholds",
		zap.Float64("anomaly_threshold", m.AnomalyThreshold),
		zap.Float64("blocking_threshold", m.BlockingThreshold),
	)

	if anomalyScore >= m.BlockingThreshold {
		m.logger.Warn("blocking request due to high anomaly score",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
		w.WriteHeader(http.StatusForbidden)
		return fmt.Errorf("request blocked due to high anomaly score") // Return error
	}

	if anomalyScore >= m.AnomalyThreshold {
		w.Header().Set("X-Suspicious-Traffic", "true")
		m.logger.Warn("marking traffic as suspicious",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
	}
	return nil
}

// getRequestHistory retrieves the request history for a given client IP and shard
func (m *MLWAF) getRequestHistory(clientIP string, shard string) []requestRecord {
	m.historyMutex.RLock()
	defer m.historyMutex.RUnlock()

	if _, ok := m.requestHistoryShards[clientIP]; !ok {
		return nil
	}
	return m.requestHistoryShards[clientIP][shard]
}

// updateRequestHistory updates the request history for a given client IP and shard
func (m *MLWAF) updateRequestHistory(clientIP string, shard string, anomalyScore float64) {
	m.historyMutex.Lock()
	defer m.historyMutex.Unlock()
	record := requestRecord{Timestamp: time.Now(), AnomalyScore: anomalyScore}

	if _, ok := m.requestHistoryShards[clientIP]; !ok {
		m.requestHistoryShards[clientIP] = make(map[string][]requestRecord)
	}

	history := m.requestHistoryShards[clientIP][shard]
	history = append(history, record)

	prunedHistory := m.pruneRequestHistory(history)
	m.requestHistoryShards[clientIP][shard] = prunedHistory

	m.logger.Debug("updated request history",
		zap.String("client_ip", clientIP),
		zap.String("shard", shard),
		zap.Float64("anomaly_score", anomalyScore),
		zap.Int("history_size", len(prunedHistory)),
	)
}

// pruneRequestHistory prunes the request history to remove old entries
func (m *MLWAF) pruneRequestHistory(history []requestRecord) []requestRecord {
	cutoff := time.Now().Add(-m.HistoryWindow)
	prunedHistory := make([]requestRecord, 0, len(history))
	for _, rec := range history {
		if rec.Timestamp.After(cutoff) {
			prunedHistory = append(prunedHistory, rec)
		}
	}
	if len(prunedHistory) > m.MaxHistoryEntries {
		prunedHistory = prunedHistory[len(prunedHistory)-m.MaxHistoryEntries:]
	}
	return prunedHistory
}

// calculateAnomalyScore calculates the anomaly score for a request
func (m *MLWAF) calculateAnomalyScore(requestSize int64, headerCount int, queryParamCount int, pathSegmentCount int, history []requestRecord, httpMethod string, userAgent string, referrer string) float64 {
	score := 0.0

	score += m.calculateRequestSizeScore(requestSize)
	score += m.calculateHeaderCountScore(headerCount)
	score += m.calculateQueryParamCountScore(queryParamCount)
	score += m.calculatePathSegmentCountScore(pathSegmentCount)
	score += m.calculateHttpMethodScore(httpMethod)
	score += m.calculateUserAgentScore(userAgent)
	score += m.calculateReferrerScore(referrer)
	score += m.calculateRequestFrequencyScore(history)
	score += m.calculateCorrelationScore(history)

	m.logger.Debug("total anomaly score calculated",
		zap.Float64("total_score", score),
	)

	return score
}

// calculateRequestSizeScore calculates the anomaly score contribution from request size
func (m *MLWAF) calculateRequestSizeScore(requestSize int64) float64 {
	normalizedRequestSize := m.normalizeValue(float64(requestSize), float64(m.NormalRequestSizeRangeMin), float64(m.NormalRequestSizeRangeMax))
	score := m.RequestSizeWeight * normalizedRequestSize

	m.logger.Debug("request size contribution to anomaly score",
		zap.Float64("normalized_request_size", normalizedRequestSize),
		zap.Float64("weight", m.RequestSizeWeight),
		zap.Float64("contribution", score),
	)
	return score
}

// calculateHeaderCountScore calculates the anomaly score contribution from header count
func (m *MLWAF) calculateHeaderCountScore(headerCount int) float64 {
	normalizedHeaderCount := m.normalizeValue(float64(headerCount), float64(m.NormalHeaderCountMin), float64(m.NormalHeaderCountMax))
	score := m.HeaderCountWeight * normalizedHeaderCount

	m.logger.Debug("header count contribution to anomaly score",
		zap.Float64("normalized_header_count", normalizedHeaderCount),
		zap.Float64("weight", m.HeaderCountWeight),
		zap.Float64("contribution", score),
	)
	return score
}

// calculateQueryParamCountScore calculates the anomaly score contribution from query parameter count
func (m *MLWAF) calculateQueryParamCountScore(queryParamCount int) float64 {
	normalizedQueryParamCount := m.normalizeValue(float64(queryParamCount), float64(m.NormalQueryParamCountMin), float64(m.NormalQueryParamCountMax))
	score := m.QueryParamCountWeight * normalizedQueryParamCount

	m.logger.Debug("query parameter count contribution to anomaly score",
		zap.Float64("normalized_query_param_count", normalizedQueryParamCount),
		zap.Float64("weight", m.QueryParamCountWeight),
		zap.Float64("contribution", score),
	)
	return score
}

// calculatePathSegmentCountScore calculates the anomaly score contribution from path segment count
func (m *MLWAF) calculatePathSegmentCountScore(pathSegmentCount int) float64 {
	normalizedPathSegmentCount := m.normalizeValue(float64(pathSegmentCount), float64(m.NormalPathSegmentCountMin), float64(m.NormalPathSegmentCountMax))
	score := m.PathSegmentCountWeight * normalizedPathSegmentCount

	m.logger.Debug("path segment count contribution to anomaly score",
		zap.Float64("normalized_path_segment_count", normalizedPathSegmentCount),
		zap.Float64("weight", m.PathSegmentCountWeight),
		zap.Float64("contribution", score),
	)
	return score
}

// calculateHttpMethodScore calculates the anomaly score contribution from the HTTP method
func (m *MLWAF) calculateHttpMethodScore(httpMethod string) float64 {
	score := 0.0
	if m.HTTPMethodWeight > 0 && len(m.NormalHTTPMethods) > 0 {
		isNormalMethod := false
		for _, method := range m.NormalHTTPMethods {
			if httpMethod == method {
				isNormalMethod = true
				break
			}
		}
		if !isNormalMethod {
			score = m.HTTPMethodWeight
			m.logger.Debug("HTTP method contribution to anomaly score",
				zap.String("http_method", httpMethod),
				zap.Float64("weight", m.HTTPMethodWeight),
				zap.Float64("contribution", m.HTTPMethodWeight),
			)
		}
	}
	return score
}

// calculateUserAgentScore calculates the anomaly score contribution from the User-Agent
func (m *MLWAF) calculateUserAgentScore(userAgent string) float64 {
	score := 0.0
	if m.UserAgentWeight > 0 && len(m.NormalUserAgents) > 0 {
		isNormalUserAgent := false
		for _, ua := range m.NormalUserAgents {
			if strings.Contains(userAgent, ua) {
				isNormalUserAgent = true
				break
			}
		}
		if !isNormalUserAgent {
			score = m.UserAgentWeight
			m.logger.Debug("User-Agent contribution to anomaly score",
				zap.String("user_agent", userAgent),
				zap.Float64("weight", m.UserAgentWeight),
				zap.Float64("contribution", m.UserAgentWeight),
			)
		}
	}
	return score
}

// calculateReferrerScore calculates the anomaly score contribution from the Referer header
func (m *MLWAF) calculateReferrerScore(referrer string) float64 {
	score := 0.0
	if m.ReferrerWeight > 0 && len(m.NormalReferrers) > 0 {
		isNormalReferrer := false
		for _, ref := range m.NormalReferrers {
			if strings.Contains(referrer, ref) {
				isNormalReferrer = true
				break
			}
		}
		if !isNormalReferrer {
			score = m.ReferrerWeight
			m.logger.Debug("Referrer contribution to anomaly score",
				zap.String("referrer", referrer),
				zap.Float64("weight", m.ReferrerWeight),
				zap.Float64("contribution", m.ReferrerWeight),
			)
		}
	}
	return score
}

// calculateRequestFrequencyScore calculates the anomaly score contribution from request frequency
func (m *MLWAF) calculateRequestFrequencyScore(history []requestRecord) float64 {
	score := 0.0
	if m.RequestFrequencyWeight > 0 && len(history) > 0 {
		timeWindow := m.HistoryWindow.Seconds()
		requestCount := float64(len(history))
		frequency := requestCount / timeWindow
		score = m.RequestFrequencyWeight * frequency
		m.logger.Debug("request frequency contribution to anomaly score",
			zap.Float64("frequency", frequency),
			zap.Float64("weight", m.RequestFrequencyWeight),
			zap.Float64("contribution", m.RequestFrequencyWeight*frequency),
		)
	}
	return score
}

// calculateCorrelationScore calculates the anomaly score contribution from request correlation
func (m *MLWAF) calculateCorrelationScore(history []requestRecord) float64 {
	correlationScore := 0.0
	for _, record := range history {
		timeDiff := time.Since(record.Timestamp).Seconds()
		if record.AnomalyScore >= m.AnomalyThreshold {
			timeWeight := math.Exp(-timeDiff / 60)
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
	return correlationScore
}

// normalizeValue normalizes a value based on a min and max range
func (m *MLWAF) normalizeValue(value float64, min float64, max float64) float64 {
	if min == max {
		return 0.0
	}
	if value < min {
		return (min - value) / (min + 1)
	} else if value > max {
		return math.Log((value-max)/(max+1) + 1)
	}
	return 0.0
}

// parseMLWAFCaddyfile parses the Caddyfile directive.
func parseMLWAFCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := MLWAF{
		RequestSizeWeight:      1.0, // Default weights
		HeaderCountWeight:      1.0,
		QueryParamCountWeight:  1.0,
		PathSegmentCountWeight: 1.0,
		RequestFrequencyWeight: 1.0,             // Default weight for request frequency
		HTTPMethodWeight:       0.0,             // Default weight for HTTP method
		UserAgentWeight:        0.0,             // Default weight for user agent
		ReferrerWeight:         0.0,             // Default weight for referrer
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
