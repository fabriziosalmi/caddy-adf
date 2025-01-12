package caddyadf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Default score for missing features
const defaultFeatureScore = 0.1

// Feature thresholds
const (
	smallRequestSizeThreshold    = 500
	mediumRequestSizeThreshold   = 2000
	smallHeaderCountThreshold    = 10
	mediumHeaderCountThreshold   = 20
	smallQueryParamCount         = 3
	mediumQueryParamCount        = 10
	singlePathSegmentThreshold   = 1
	multiplePathSegmentThreshold = 5
)

// mlModel encapsulates the ML scoring model.
type mlModel struct {
	featureScores map[string]float64
	mu            sync.RWMutex
	logger        *zap.Logger
}

var model *mlModel

func init() {
	model = newMLModel()
}

// newMLModel initializes a new mlModel instance.
func newMLModel() *mlModel {
	return &mlModel{
		featureScores: make(map[string]float64),
	}
}

// loadModel loads a model file and populates feature scores.
func (m *mlModel) loadModel(modelPath string, logger *zap.Logger) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := os.Open(modelPath)
	if err != nil {
		return fmt.Errorf("failed to open model file %q: %w", modelPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			logger.Debug("skipping malformed line in model file", zap.Int("line_number", lineNumber), zap.String("line", line))
			continue
		}
		feature := strings.TrimSpace(parts[0])
		score, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err != nil {
			logger.Debug("error parsing score, skipping line", zap.Int("line_number", lineNumber), zap.String("line", line), zap.Error(err))
			continue
		}
		m.featureScores[feature] = score
		logger.Debug("loaded feature score", zap.String("feature", feature), zap.Float64("score", score))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading model file: %w", err)
	}

	logger.Info("ML model loaded successfully", zap.Int("features_loaded", len(m.featureScores)))
	return nil
}

// normalizeFeature dynamically maps input feature values into meaningful model keys.
func normalizeFeature(feature string, value interface{}) string {
	switch feature {
	case "request_size":
		if size, ok := value.(int64); ok {
			if size == 0 {
				return "request_size_small"
			} else if size < 1000 {
				return "request_size_medium"
			} else {
				return "request_size_large"
			}
		}
	case "header_count":
		if count, ok := value.(int); ok {
			if count <= 5 {
				return "header_count_small"
			} else if count <= 15 {
				return "header_count_medium"
			} else {
				return "header_count_large"
			}
		}

	case "query_param_count":
		if count, ok := value.(int); ok {
			if count <= 1 {
				return "query_param_count_few"
			} else if count <= 5 {
				return "query_param_count_medium"
			} else {
				return "query_param_count_many"
			}
		}
	case "path_segment_count":
		if count, ok := value.(int); ok {
			if count == 1 {
				return "path_segment_count_single"
			} else if count <= 3 {
				return "path_segment_count_few"
			} else {
				return "path_segment_count_many"
			}
		}
	case "user_agent":
		if ua, ok := value.(string); ok {
			if strings.Contains(ua, "python-requests") {
				return "user_agent_python_requests"
			} else if strings.Contains(ua, "Mozilla") {
				if strings.Contains(ua, "fab") {
					return "user_agent_fab"
				}
				return "user_agent_mozilla"
			} else if strings.Contains(ua, "fab") {
				return "user_agent_fab"
			} else {
				return "user_agent_other"
			}
		}

	case "referrer":
		if ref, ok := value.(string); ok {
			if ref == "" {
				return "referrer_empty"
			} else if strings.Contains(ref, "example.com") {
				return "referrer_example"
			} else if strings.Contains(ref, "evil.com") {
				return "referrer_https://evil.com"
			} else {
				return "referrer_other"
			}
		}

	}
	return fmt.Sprintf("%s_%v", feature, value)
}

// calculateMLScore computes the anomaly score based on normalized features.
func (m *mlModel) calculateMLScore(requestSize int64, headerCount, queryParamCount, pathSegmentCount int,
	httpMethod, userAgent, referrer string, logger *zap.Logger) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	features := []string{
		normalizeFeature("request_size", requestSize),
		normalizeFeature("header_count", headerCount),
		normalizeFeature("query_param_count", queryParamCount),
		normalizeFeature("path_segment_count", pathSegmentCount),
		normalizeFeature("http_method", httpMethod),
		normalizeFeature("user_agent", userAgent),
		normalizeFeature("referrer", referrer),
	}

	score := 0.0
	seenFeatures := make(map[string]bool)

	for _, feature := range features {
		if mlScore, exists := m.featureScores[feature]; exists {
			score += mlScore
		} else if !seenFeatures[feature] {
			seenFeatures[feature] = true
			logger.Debug("Feature not found in model, using default score", zap.String("feature", feature), zap.Float64("default_score", defaultFeatureScore))
			score += defaultFeatureScore
		}
	}

	return score
}

// getFeatures returns all features and their scores.
func (m *mlModel) getFeatures(requestSize int64, headerCount, queryParamCount, pathSegmentCount int,
	httpMethod, userAgent, referrer string, logger *zap.Logger) map[string]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	features := []string{
		normalizeFeature("request_size", requestSize),
		normalizeFeature("header_count", headerCount),
		normalizeFeature("query_param_count", queryParamCount),
		normalizeFeature("path_segment_count", pathSegmentCount),
		normalizeFeature("http_method", httpMethod),
		normalizeFeature("user_agent", userAgent),
		normalizeFeature("referrer", referrer),
	}

	scores := make(map[string]float64)
	seenFeatures := make(map[string]bool)

	for _, feature := range features {
		if mlScore, exists := m.featureScores[feature]; exists {
			scores[feature] = mlScore
		} else if !seenFeatures[feature] {
			seenFeatures[feature] = true
			scores[feature] = defaultFeatureScore
			logger.Debug("Feature not found in model, using default score", zap.String("feature", feature), zap.Float64("default_score", defaultFeatureScore))

		}
	}
	return scores
}

// UpdateFeatureScores adds or updates a feature score dynamically.
func (m *mlModel) UpdateFeatureScores(feature string, score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.featureScores[feature] = score
	m.logger.Info("Feature score updated", zap.String("feature", feature), zap.Float64("score", score))
}

// initializeMLModel initializes the ML model from the specified file path.
func initializeMLModel(modelPath string, logger *zap.Logger) {
	if modelPath == "" {
		logger.Info("ML model initialization skipped; no model path provided")
		return
	}

	err := model.loadModel(modelPath, logger)
	if err != nil {
		logger.Fatal("Failed to load ML model", zap.String("model_path", modelPath), zap.Error(err))
	}

	logger.Info("ML model initialized successfully", zap.String("model_path", modelPath))
	model.logger = logger
}
