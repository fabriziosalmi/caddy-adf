package caddyadf

import (
	"fmt"
	"net/http"
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
	AnomalyThreshold             float64               `json:"anomaly_threshold,omitempty"`
	BlockingThreshold            float64               `json:"blocking_threshold,omitempty"`
	NormalRequestSizeRangeMin    int                   `json:"normal_request_size_min,omitempty"`
	NormalRequestSizeRangeMax    int                   `json:"normal_request_size_max,omitempty"`
	NormalHeaderCountMin         int                   `json:"normal_header_count_min,omitempty"`
	NormalHeaderCountMax         int                   `json:"normal_header_count_max,omitempty"`
	NormalQueryParamCountMin     int                   `json:"normal_query_param_count_min,omitempty"`
	NormalQueryParamCountMax     int                   `json:"normal_query_param_count_max,omitempty"`
	NormalPathSegmentCountMin    int                   `json:"normal_path_segment_count_min,omitempty"`
	NormalPathSegmentCountMax    int                   `json:"normal_path_segment_count_max,omitempty"`
	RequestSizeWeight            float64               `json:"request_size_weight,omitempty"`
	HeaderCountWeight            float64               `json:"header_count_weight,omitempty"`
	QueryParamCountWeight        float64               `json:"query_param_count_weight,omitempty"`
	PathSegmentCountWeight       float64               `json:"path_segment_count_weight,omitempty"`
	RequestFrequencyWeight       float64               `json:"request_frequency_weight,omitempty"`
	HistoryWindow                time.Duration         `json:"history_window,omitempty"`
	MaxHistoryEntries            int                   `json:"max_history_entries,omitempty"`
	NormalHTTPMethods            []string              `json:"normal_http_methods,omitempty"`
	NormalUserAgents             []string              `json:"normal_user_agents,omitempty"`
	NormalReferrers              []string              `json:"normal_referrers,omitempty"`
	HTTPMethodWeight             float64               `json:"http_method_weight,omitempty"`
	UserAgentWeight              float64               `json:"user_agent_weight,omitempty"`
	ReferrerWeight               float64               `json:"referrer_weight,omitempty"`
	PerPathConfig                map[string]PathConfig `json:"per_path_config,omitempty"`
	EnableML                     bool                  `json:"enable_ml,omitempty"`
	ModelPath                    string                `json:"model_path,omitempty"`
	HeaderRedactionList          []string              `json:"header_redaction_list,omitempty"`
	QueryParamRedactionList      []string              `json:"query_param_redaction_list,omitempty"`
	DynamicThresholdEnabled      bool                  `json:"dynamic_threshold_enabled,omitempty"`
	DynamicThresholdFactor       float64               `json:"dynamic_threshold_factor,omitempty"`
	dynamicAnomalyThreshold      map[string]float64
	dynamicAnomalyThresholdMutex sync.RWMutex
	DefaultPathConfig            PathConfig `json:"default_path_config,omitempty"`
	requestNormalizer            *RequestNormalizer
	adminEndpoint                *AdminEndpoint
	normalizationConfig          map[string]string `json:"normalization_config,omitempty"`

	numShards int

	logger           *zap.Logger
	anomalyScorer    *AnomalyScorer         // Anomaly scorer instance
	historyManager   *RequestHistoryManager //Request history manager
	requestSanitizer *RequestSanitizer      // Request sanitizer

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
	blocked    bool
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
		zap.Bool("enable_ml", m.EnableML),
		zap.String("model_path", m.ModelPath),
		zap.Bool("dynamic_threshold_enabled", m.DynamicThresholdEnabled),
		zap.Float64("dynamic_threshold_factor", m.DynamicThresholdFactor),
	)

	m.numShards = 32 // Initialize with a reasonable number of shards

	// Initialize AnomalyScorer
	m.anomalyScorer = NewAnomalyScorer(m, m.logger)
	// Initialize RequestHistoryManager
	m.historyManager = NewRequestHistoryManager(m.numShards, m.HistoryWindow, m.MaxHistoryEntries, m.logger)
	// Initialize RequestSanitizer
	m.requestSanitizer = NewRequestSanitizer(m.HeaderRedactionList, m.QueryParamRedactionList)
	// Initialize RequestNormalizer
	m.requestNormalizer = NewRequestNormalizer()
	// Initialize Admin Endpoint
	m.adminEndpoint = NewAdminEndpoint(m, m.logger)

	if m.DynamicThresholdEnabled {
		m.dynamicAnomalyThreshold = make(map[string]float64)
	}
	for feature, normalizerType := range m.normalizationConfig {
		m.requestNormalizer.SetNormalizer(feature, NormalizerType(normalizerType))
		m.logger.Debug("normalization configured for feature",
			zap.String("feature", feature),
			zap.String("normalizer", normalizerType),
		)
	}

	if m.EnableML {
		initializeMLModel(m.ModelPath, m.logger)

		// Configure feature mappers based on the model's expected structure
		// **IMPORTANT:** Adapt this section based on how your pre-trained model is structured.
		// Inspect your 'pre-trained.model' to see the exact feature names.

		// Scenario 1: Model uses simple feature names (e.g., "request_size")
		// In this case, we don't set specific mappers, and rely on the default
		// normalizeFeature behavior (after the suggested modification).

		// Scenario 2: Model uses value-based feature names (e.g., "request_size_0")
		// Add mappers to explicitly define how features are normalized.
		model.SetFeatureMapper("request_size", []string{}, "", m.logger)
		model.SetFeatureMapper("header_count", []string{}, "", m.logger)
		model.SetFeatureMapper("query_param_count", []string{}, "", m.logger)
		model.SetFeatureMapper("path_segment_count", []string{}, "", m.logger)
		model.SetFeatureMapper("http_method", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}, "", m.logger)
		model.SetFeatureMapper("user_agent", []string{"fab", "Mozilla", "Chrome", "Safari", "python-requests/2.32.3", "curl"}, "", m.logger)
		model.SetFeatureMapper("referrer", []string{"https://example.com", "https://trusted.example.org"}, "", m.logger)

		m.logger.Info("ML Feature Mappers configured.")
	}

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

	if m.DynamicThresholdEnabled && m.DynamicThresholdFactor <= 0 {
		return fmt.Errorf("dynamic_threshold_factor must be a positive value")
	}

	// Validate per-path configurations
	if (m.DefaultPathConfig != PathConfig{}) {
		if m.DefaultPathConfig.AnomalyThreshold >= m.DefaultPathConfig.BlockingThreshold {
			return fmt.Errorf("default per-path anomaly_threshold should be less than blocking_threshold")
		}
	}

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

// getShard returns the shard number for a given client IP
func (m *MLWAF) getShard(clientIP string) string {
	return m.historyManager.getShard(clientIP)
}

func (m *MLWAF) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	unmarshaler := NewCaddyfileUnmarshaler()
	return unmarshaler.UnmarshalCaddyfile(m, d)
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (m *MLWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// First check if this is a request for the admin endpoint
	if strings.HasPrefix(r.URL.Path, "/ml_waf") {
		return m.adminEndpoint.ServeHTTP(w, r, next)
	}

	startTime := time.Now()
	clientIP := r.RemoteAddr
	shard := m.getShard(clientIP)

	// Collect request attributes
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
	sanitizedHeaders := m.requestSanitizer.SanitizeHeaders(r.Header)
	sanitizedQueryParams := m.requestSanitizer.SanitizeQueryParams(r.URL.Query())

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
	// Fetch request history for anomaly score calculation
	history := m.historyManager.GetRequestHistory(clientIP, shard)

	// Calculate anomaly score using the AnomalyScorer
	traditionalScore, mlScore, anomalyScore := m.anomalyScorer.CalculateAnomalyScore(
		requestSize, headerCount, queryParamCount, pathSegmentCount, history, httpMethod, userAgent, referrer,
	)

	m.logger.Debug("calculated anomaly score",
		zap.String("client_ip", clientIP),
		zap.Float64("traditional_score", traditionalScore),
		zap.Float64("ml_score", mlScore),
		zap.Float64("anomaly_score", anomalyScore),
		zap.String("path", r.URL.Path),
	)

	anomalyThreshold := m.AnomalyThreshold
	blockingThreshold := m.BlockingThreshold
	// Handle per-path configuration
	pathConfig, ok := m.PerPathConfig[r.URL.Path]
	if !ok {
		pathConfig = m.DefaultPathConfig
		m.logger.Debug("using default per-path thresholds",
			zap.String("path", r.URL.Path),
			zap.Float64("anomaly_threshold", anomalyThreshold),
			zap.Float64("blocking_threshold", blockingThreshold),
		)

	} else {
		m.logger.Debug("using per-path thresholds",
			zap.String("path", r.URL.Path),
			zap.Float64("anomaly_threshold", pathConfig.AnomalyThreshold),
			zap.Float64("blocking_threshold", pathConfig.BlockingThreshold),
		)
		anomalyThreshold = pathConfig.AnomalyThreshold
		blockingThreshold = pathConfig.BlockingThreshold

	}

	if m.DynamicThresholdEnabled {
		anomalyThreshold = m.calculateDynamicThreshold(r.URL.Path, anomalyThreshold)
		m.logger.Debug("using dynamic thresholds",
			zap.String("path", r.URL.Path),
			zap.Float64("dynamic_anomaly_threshold", anomalyThreshold),
		)
	}
	m.logger.Debug("using final thresholds",
		zap.String("path", r.URL.Path),
		zap.Float64("final_anomaly_threshold", anomalyThreshold),
		zap.Float64("final_blocking_threshold", blockingThreshold),
	)

	mlFeatures := model.getFeatures(requestSize, headerCount, queryParamCount, pathSegmentCount, httpMethod, userAgent, referrer, m.logger)
	m.logger.Debug("ML features and scores", zap.Any("scores", mlFeatures))

	// Determine response action
	statusCode := http.StatusOK
	blocked := false

	if anomalyScore >= blockingThreshold {
		blocked = true
		statusCode = http.StatusForbidden
		w.Header().Set("X-ML-WAF-Blocked", "true")
		w.Header().Set("X-ML-WAF-Anomaly-Score", fmt.Sprintf("%f", anomalyScore))
		http.Error(w, fmt.Sprintf("Forbidden, anomaly score: %f", anomalyScore), http.StatusForbidden)

	}
	// Response wrapper to capture status code
	rw := &responseWriterWrapper{ResponseWriter: w, statusCode: statusCode, blocked: blocked}

	if blocked {
		m.logger.Warn("blocking request due to high anomaly score",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
		m.historyManager.UpdateRequestHistory(clientIP, shard, anomalyScore)
		return nil // Stop further middleware processing
	}

	if anomalyScore >= anomalyThreshold {
		w.Header().Set("X-Suspicious-Traffic", "true")
		m.logger.Warn("marking traffic as suspicious",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
	}

	// Process next handler
	err := next.ServeHTTP(rw, r)

	// Log request processing duration
	duration := time.Since(startTime)
	m.logger.Debug("request processed",
		zap.String("client_ip", clientIP),
		zap.Int("status_code", rw.statusCode),
		zap.Duration("duration", duration),
		zap.String("path", r.URL.Path),
	)

	if !blocked {
		m.historyManager.UpdateRequestHistory(clientIP, shard, anomalyScore)
	}

	return err
}

// calculateDynamicThreshold calculates the dynamic anomaly threshold based on a moving average
func (m *MLWAF) calculateDynamicThreshold(path string, baseThreshold float64) float64 {
	m.dynamicAnomalyThresholdMutex.Lock()
	defer m.dynamicAnomalyThresholdMutex.Unlock()
	if _, ok := m.dynamicAnomalyThreshold[path]; !ok {
		m.dynamicAnomalyThreshold[path] = baseThreshold
		return baseThreshold
	}

	m.dynamicAnomalyThreshold[path] = (m.dynamicAnomalyThreshold[path] + baseThreshold) / 2
	newThreshold := m.dynamicAnomalyThreshold[path] * m.DynamicThresholdFactor

	return newThreshold

}

// handlePerPathRequest handles requests based on per-path configuration
func (m *MLWAF) handlePerPathRequest(w http.ResponseWriter, clientIP string, r *http.Request, anomalyScore float64, pathConfig PathConfig) bool {

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
		return true // return true to indicate blocked
	}

	if anomalyScore >= pathConfig.AnomalyThreshold {
		w.Header().Set("X-Suspicious-Traffic", "true")
		m.logger.Warn("marking traffic as suspicious",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
	}
	return false // return false if not blocked
}

// handleGlobalRequest handles requests based on global configuration
func (m *MLWAF) handleGlobalRequest(w http.ResponseWriter, clientIP string, r *http.Request, anomalyScore float64) bool {
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
		return true // return true to indicate blocked
	}

	if anomalyScore >= m.AnomalyThreshold {
		w.Header().Set("X-Suspicious-Traffic", "true")
		m.logger.Warn("marking traffic as suspicious",
			zap.String("client_ip", clientIP),
			zap.Float64("anomaly_score", anomalyScore),
			zap.String("path", r.URL.Path),
		)
	}
	return false // return false if not blocked
}

// parseMLWAFCaddyfile parses the Caddyfile directive.
func parseMLWAFCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := MLWAF{
		RequestSizeWeight:       1.0, // Default weights
		HeaderCountWeight:       1.0,
		QueryParamCountWeight:   1.0,
		PathSegmentCountWeight:  1.0,
		RequestFrequencyWeight:  1.0,             // Default weight for request frequency
		HTTPMethodWeight:        0.0,             // Default weight for HTTP method
		UserAgentWeight:         0.0,             // Default weight for user agent
		ReferrerWeight:          0.0,             // Default weight for referrer
		HistoryWindow:           1 * time.Minute, // Default history window
		MaxHistoryEntries:       10,              // Default max history entries
		HeaderRedactionList:     []string{"Authorization", "Cookie", "Set-Cookie"},
		QueryParamRedactionList: []string{"token", "password", "api_key"},
		DynamicThresholdEnabled: false,
		DynamicThresholdFactor:  1.0,
		DefaultPathConfig:       PathConfig{},
		normalizationConfig:     make(map[string]string),
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
