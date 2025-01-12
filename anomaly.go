package caddyadf

import (
	"math"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AnomalyScorer encapsulates the logic for calculating anomaly scores.
type AnomalyScorer struct {
	MLWAF  *MLWAF // Reference to the main MLWAF struct for configs
	logger *zap.Logger
}

// NewAnomalyScorer creates a new AnomalyScorer.
func NewAnomalyScorer(waf *MLWAF, logger *zap.Logger) *AnomalyScorer {
	return &AnomalyScorer{MLWAF: waf, logger: logger}
}

// CalculateAnomalyScore calculates the anomaly score for a request
func (as *AnomalyScorer) CalculateAnomalyScore(requestSize int64, headerCount int, queryParamCount int, pathSegmentCount int, history []requestRecord, httpMethod string, userAgent string, referrer string) (float64, float64, float64) {
	score := 0.0

	score += as.calculateRequestSizeScore(requestSize)
	score += as.calculateHeaderCountScore(headerCount)
	score += as.calculateQueryParamCountScore(queryParamCount)
	score += as.calculatePathSegmentCountScore(pathSegmentCount)
	score += as.calculateHttpMethodScore(httpMethod)
	if as.MLWAF.UserAgentWeight > 0 {
		score += as.calculateUserAgentScore(userAgent)
	}
	if as.MLWAF.ReferrerWeight > 0 {
		score += as.calculateReferrerScore(referrer)
	}
	score += as.calculateRequestFrequencyScore(history)
	score += as.calculateCorrelationScore(history)

	mlScore := 0.0
	if as.MLWAF.EnableML {
		mlScore = model.calculateMLScore(requestSize, headerCount, queryParamCount, pathSegmentCount, httpMethod, userAgent, referrer, as.logger)

		as.logger.Debug("anomaly score calculation", zap.String("component", "ml_score"), zap.Float64("score", mlScore))
	}
	totalScore := score + mlScore
	as.logger.Debug("anomaly score calculation", zap.String("component", "total_score"), zap.Float64("score", totalScore))

	return score, mlScore, totalScore
}

// calculateRequestSizeScore calculates the anomaly score contribution from request size
func (as *AnomalyScorer) calculateRequestSizeScore(requestSize int64) float64 {
	normalizedRequestSize := as.MLWAF.requestNormalizer.NormalizeValue("request_size", float64(requestSize), float64(as.MLWAF.NormalRequestSizeRangeMin), float64(as.MLWAF.NormalRequestSizeRangeMax))
	score := 0.0
	if as.MLWAF.RequestSizeWeight > 0 {
		score = as.MLWAF.RequestSizeWeight * normalizedRequestSize
		as.logger.Debug("anomaly score calculation",
			zap.String("component", "request_size"),
			zap.Float64("normalized_value", normalizedRequestSize),
			zap.Float64("weight", as.MLWAF.RequestSizeWeight),
			zap.Float64("score", score),
		)

	}
	return score
}

// calculateHeaderCountScore calculates the anomaly score contribution from header count
func (as *AnomalyScorer) calculateHeaderCountScore(headerCount int) float64 {
	normalizedHeaderCount := as.MLWAF.requestNormalizer.NormalizeValue("header_count", float64(headerCount), float64(as.MLWAF.NormalHeaderCountMin), float64(as.MLWAF.NormalHeaderCountMax))
	score := 0.0
	if as.MLWAF.HeaderCountWeight > 0 {
		score = as.MLWAF.HeaderCountWeight * normalizedHeaderCount
		as.logger.Debug("anomaly score calculation",
			zap.String("component", "header_count"),
			zap.Float64("normalized_value", normalizedHeaderCount),
			zap.Float64("weight", as.MLWAF.HeaderCountWeight),
			zap.Float64("score", score),
		)
	}
	return score
}

// calculateQueryParamCountScore calculates the anomaly score contribution from query parameter count
func (as *AnomalyScorer) calculateQueryParamCountScore(queryParamCount int) float64 {
	normalizedQueryParamCount := as.MLWAF.requestNormalizer.NormalizeValue("query_param_count", float64(queryParamCount), float64(as.MLWAF.NormalQueryParamCountMin), float64(as.MLWAF.NormalQueryParamCountMax))
	score := 0.0
	if as.MLWAF.QueryParamCountWeight > 0 {
		score = as.MLWAF.QueryParamCountWeight * normalizedQueryParamCount
		as.logger.Debug("anomaly score calculation",
			zap.String("component", "query_param_count"),
			zap.Float64("normalized_value", normalizedQueryParamCount),
			zap.Float64("weight", as.MLWAF.QueryParamCountWeight),
			zap.Float64("score", score),
		)
	}
	return score
}

// calculatePathSegmentCountScore calculates the anomaly score contribution from path segment count
func (as *AnomalyScorer) calculatePathSegmentCountScore(pathSegmentCount int) float64 {
	normalizedPathSegmentCount := as.MLWAF.requestNormalizer.NormalizeValue("path_segment_count", float64(pathSegmentCount), float64(as.MLWAF.NormalPathSegmentCountMin), float64(as.MLWAF.NormalPathSegmentCountMax))
	score := 0.0
	if as.MLWAF.PathSegmentCountWeight > 0 {
		score = as.MLWAF.PathSegmentCountWeight * normalizedPathSegmentCount
		as.logger.Debug("anomaly score calculation",
			zap.String("component", "path_segment_count"),
			zap.Float64("normalized_value", normalizedPathSegmentCount),
			zap.Float64("weight", as.MLWAF.PathSegmentCountWeight),
			zap.Float64("score", score),
		)
	}
	return score
}

// calculateHttpMethodScore calculates the anomaly score contribution from the HTTP method
func (as *AnomalyScorer) calculateHttpMethodScore(httpMethod string) float64 {
	score := 0.0
	if as.MLWAF.HTTPMethodWeight > 0 && len(as.MLWAF.NormalHTTPMethods) > 0 {
		isNormalMethod := false
		for _, method := range as.MLWAF.NormalHTTPMethods {
			if httpMethod == method {
				isNormalMethod = true
				break
			}
		}
		if !isNormalMethod {
			score = as.MLWAF.HTTPMethodWeight
			as.logger.Debug("anomaly score calculation",
				zap.String("component", "http_method"),
				zap.String("http_method", httpMethod),
				zap.Float64("weight", as.MLWAF.HTTPMethodWeight),
				zap.Float64("score", as.MLWAF.HTTPMethodWeight),
			)
		}
	}
	return score
}

// calculateUserAgentScore calculates the anomaly score contribution from the User-Agent
func (as *AnomalyScorer) calculateUserAgentScore(userAgent string) float64 {
	score := 0.0
	if as.MLWAF.UserAgentWeight > 0 && len(as.MLWAF.NormalUserAgents) > 0 {
		isNormalUserAgent := false
		for _, ua := range as.MLWAF.NormalUserAgents {
			if strings.Contains(userAgent, ua) {
				isNormalUserAgent = true
				break
			}
		}
		if !isNormalUserAgent {
			score = as.MLWAF.UserAgentWeight
			as.logger.Debug("anomaly score calculation",
				zap.String("component", "user_agent"),
				zap.String("user_agent", userAgent),
				zap.Float64("weight", as.MLWAF.UserAgentWeight),
				zap.Float64("score", as.MLWAF.UserAgentWeight),
			)
		}
	}
	return score
}

// calculateReferrerScore calculates the anomaly score contribution from the Referer header
func (as *AnomalyScorer) calculateReferrerScore(referrer string) float64 {
	score := 0.0
	normalizedReferrer := as.MLWAF.requestNormalizer.NormalizeValue("referrer", 1, 0, 1)
	if as.MLWAF.ReferrerWeight > 0 && len(as.MLWAF.NormalReferrers) > 0 {
		isNormalReferrer := false
		for _, ref := range as.MLWAF.NormalReferrers {
			if strings.Contains(referrer, ref) {
				isNormalReferrer = true
				break
			}
		}
		if !isNormalReferrer {

			score = as.MLWAF.ReferrerWeight * normalizedReferrer
			as.logger.Debug("anomaly score calculation",
				zap.String("component", "referrer"),
				zap.String("referrer", referrer),
				zap.Float64("weight", as.MLWAF.ReferrerWeight),
				zap.Float64("normalized_value", normalizedReferrer),
				zap.Float64("score", score),
			)
		} else {
			normalizedReferrer = as.MLWAF.requestNormalizer.NormalizeValue("referrer", 0, 0, 1)
			score = as.MLWAF.ReferrerWeight * normalizedReferrer
			as.logger.Debug("anomaly score calculation",
				zap.String("component", "referrer"),
				zap.String("referrer", referrer),
				zap.Float64("weight", as.MLWAF.ReferrerWeight),
				zap.Float64("normalized_value", normalizedReferrer),
				zap.Float64("score", score),
			)

		}
	}
	return score
}

// calculateRequestFrequencyScore calculates the anomaly score contribution from request frequency
func (as *AnomalyScorer) calculateRequestFrequencyScore(history []requestRecord) float64 {
	score := 0.0
	if as.MLWAF.RequestFrequencyWeight > 0 && len(history) > 0 {
		timeWindow := as.MLWAF.HistoryWindow.Seconds()
		requestCount := float64(len(history))
		frequency := requestCount / timeWindow
		score = as.MLWAF.RequestFrequencyWeight * frequency
		as.logger.Debug("anomaly score calculation",
			zap.String("component", "request_frequency"),
			zap.Float64("frequency", frequency),
			zap.Float64("weight", as.MLWAF.RequestFrequencyWeight),
			zap.Float64("score", score),
		)
	}
	return score
}

// calculateCorrelationScore calculates the anomaly score contribution from request correlation
func (as *AnomalyScorer) calculateCorrelationScore(history []requestRecord) float64 {
	correlationScore := 0.0
	for _, record := range history {
		timeDiff := time.Since(record.Timestamp).Seconds()
		if record.AnomalyScore >= as.MLWAF.AnomalyThreshold {
			timeWeight := math.Exp(-timeDiff / 60)
			severityWeight := record.AnomalyScore / as.MLWAF.BlockingThreshold

			correlationScore += 0.15 * timeWeight * severityWeight
			as.logger.Debug("anomaly score calculation",
				zap.String("component", "correlation"),
				zap.Time("record_timestamp", record.Timestamp),
				zap.Float64("record_anomaly_score", record.AnomalyScore),
				zap.Float64("time_weight", timeWeight),
				zap.Float64("severity_weight", severityWeight),
				zap.Float64("score", 0.15*timeWeight*severityWeight),
			)
		}
	}
	return correlationScore
}

// normalizeValue normalizes a value based on a min and max range
func (as *AnomalyScorer) normalizeValue(feature string, value float64, min float64, max float64) float64 {
	return as.MLWAF.requestNormalizer.NormalizeValue(feature, value, min, max)
}
