package caddyadf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"path/filepath"
	
	"go.uber.org/zap"
)

const (
	FeatureRequestSize      = "request_size"
	FeatureHeaderCount      = "header_count"
	FeatureQueryParamCount  = "query_param_count"
	FeaturePathSegmentCount = "path_segment_count"
	FeatureHTTPMethod       = "http_method"
	FeatureUserAgent        = "user_agent"
	FeatureReferrer         = "referrer"
)

// Default score for missing features
const defaultFeatureScore = 0.1

// mlModel encapsulates the ML scoring model.
type mlModel struct {
	featureScores  map[string]float64
	featureMappers map[string]featureMapper
	mu             sync.RWMutex
	logger         *zap.Logger
}

// featureMapper is a struct that contains the mapping and normalization of a single feature
type featureMapper struct {
	featureName string
	featureKeys []string
	normalizer  string
}

var model *mlModel

func init() {
	model = newMLModel()
}

// newMLModel initializes a new mlModel instance.
func newMLModel() *mlModel {
	return &mlModel{
		featureScores:  make(map[string]float64),
		featureMappers: make(map[string]featureMapper),
	}
}

// loadModel loads a model file and populates feature scores.
func (m *mlModel) loadModel(modelPath string, logger *zap.Logger) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	const safeDir = "/home/user/models/"
	absPath, err := filepath.Abs(filepath.Join(safeDir, modelPath))
	if err != nil || !strings.HasPrefix(absPath, safeDir) {
		return fmt.Errorf("invalid model path: %q", modelPath)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return fmt.Errorf("failed to open model file %q: %w", absPath, err)
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
func (m *mlModel) normalizeFeature(feature string, value interface{}, logger *zap.Logger) string {
	if mapper, ok := m.featureMappers[feature]; ok {
		return fmt.Sprintf("%s_%v", mapper.featureName, value)
	}

	logger.Warn("Unrecognized feature, using default value", zap.String("feature", feature))
	return feature // Return the feature name directly
}

// calculateMLScore computes the anomaly score based on normalized features.
func (m *mlModel) calculateMLScore(requestSize int64, headerCount, queryParamCount, pathSegmentCount int,
	httpMethod, userAgent, referrer string, logger *zap.Logger) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	features := []string{
		m.normalizeFeature("request_size", requestSize, logger),
		m.normalizeFeature("header_count", headerCount, logger),
		m.normalizeFeature("query_param_count", queryParamCount, logger),
		m.normalizeFeature("path_segment_count", pathSegmentCount, logger),
		m.normalizeFeature("http_method", httpMethod, logger),
		m.normalizeFeature("user_agent", userAgent, logger),
		m.normalizeFeature("referrer", referrer, logger),
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
		m.normalizeFeature("request_size", requestSize, logger),
		m.normalizeFeature("header_count", headerCount, logger),
		m.normalizeFeature("query_param_count", queryParamCount, logger),
		m.normalizeFeature("path_segment_count", pathSegmentCount, logger),
		m.normalizeFeature("http_method", httpMethod, logger),
		m.normalizeFeature("user_agent", userAgent, logger),
		m.normalizeFeature("referrer", referrer, logger),
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

// setFeatureMapper adds a new feature mapper dynamically.
func (m *mlModel) SetFeatureMapper(feature string, keys []string, normalizer string, logger *zap.Logger) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.featureMappers[feature] = featureMapper{featureName: feature, featureKeys: keys, normalizer: normalizer}
	logger.Info("Feature mapper configured", zap.String("feature", feature), zap.Any("keys", keys), zap.String("normalizer", normalizer))
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
