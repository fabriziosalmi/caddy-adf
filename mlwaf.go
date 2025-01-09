package caddymlf

import (
	"fmt"
	"net/http"
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

// Validate ensures the configuration is valid.
func (m *MLWAF) Validate() error {
	if m.AnomalyThreshold >= m.BlockingThreshold {
		return fmt.Errorf("anomaly_threshold should be less than blocking_threshold")
	}
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
	return nil
}

// ServeHTTP handles the HTTP request.
func (m *MLWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	startTime := time.Now()
	clientIP := r.RemoteAddr
	requestSize := r.ContentLength
	headerCount := len(r.Header)
	queryParamCount := len(r.URL.Query())
	pathSegmentCount := len(strings.Split(strings.Trim(r.URL.Path, "/"), "/"))

	m.historyMutex.Lock()
	history := m.requestHistory[clientIP]
	m.historyMutex.Unlock()

	anomalyScore := m.calculateAnomalyScore(requestSize, headerCount, queryParamCount, pathSegmentCount, history)

	m.logger.Debug("calculated anomaly score",
		zap.String("client_ip", clientIP),
		zap.Int64("request_size", requestSize),
		zap.Int("header_count", headerCount),
		zap.Int("query_param_count", queryParamCount),
		zap.Int("path_segment_count", pathSegmentCount),
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

func (m *MLWAF) calculateAnomalyScore(requestSize int64, headerCount int, queryParamCount int, pathSegmentCount int, history []requestRecord) float64 {
	score := 0.0

	// Base anomaly score calculation (same as before)
	if m.RequestSizeWeight > 0 {
		if m.NormalRequestSizeRangeMin > 0 && requestSize < int64(m.NormalRequestSizeRangeMin) {
			score += m.RequestSizeWeight * float64(m.NormalRequestSizeRangeMin-int(requestSize)) / float64(m.NormalRequestSizeRangeMin)
		} else if m.NormalRequestSizeRangeMax > 0 && requestSize > int64(m.NormalRequestSizeRangeMax) {
			score += m.RequestSizeWeight * float64(int(requestSize)-m.NormalRequestSizeRangeMax) / float64(m.NormalRequestSizeRangeMax)
		}
	}

	if m.HeaderCountWeight > 0 {
		if m.NormalHeaderCountMin > 0 && headerCount < m.NormalHeaderCountMin {
			score += m.HeaderCountWeight * float64(m.NormalHeaderCountMin-headerCount) / float64(m.NormalHeaderCountMin)
		} else if m.NormalHeaderCountMax > 0 && headerCount > m.NormalHeaderCountMax {
			score += m.HeaderCountWeight * float64(headerCount-m.NormalHeaderCountMax) / float64(m.NormalHeaderCountMax)
		}
	}

	if m.QueryParamCountWeight > 0 {
		if m.NormalQueryParamCountMin > 0 && queryParamCount < m.NormalQueryParamCountMin {
			score += m.QueryParamCountWeight * float64(m.NormalQueryParamCountMin-queryParamCount) / float64(m.NormalQueryParamCountMin)
		} else if m.NormalQueryParamCountMax > 0 && queryParamCount > m.NormalQueryParamCountMax {
			score += m.QueryParamCountWeight * float64(queryParamCount-m.NormalQueryParamCountMax) / float64(m.NormalQueryParamCountMax)
		}
	}

	if m.PathSegmentCountWeight > 0 {
		if m.NormalPathSegmentCountMin > 0 && pathSegmentCount < m.NormalPathSegmentCountMin {
			score += m.PathSegmentCountWeight * float64(m.NormalPathSegmentCountMin-pathSegmentCount) / float64(m.NormalPathSegmentCountMin)
		} else if m.NormalPathSegmentCountMax > 0 && pathSegmentCount > m.NormalPathSegmentCountMax {
			score += m.PathSegmentCountWeight * float64(pathSegmentCount-m.NormalPathSegmentCountMax) / float64(m.NormalPathSegmentCountMax)
		}
	}

	// Apply correlation logic based on request history
	for _, record := range history {
		if record.AnomalyScore >= m.AnomalyThreshold {
			score += 0.5 // Example: Increase score if previous requests were suspicious
		}
	}

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
