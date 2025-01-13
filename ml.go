package caddyadf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

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
		logger:         zap.L().Named("ml_model"), // Initialize logger here
	}
}

// loadModel loads a model file and populates feature scores.
func (m *mlModel) loadModel(modelPath string, logger *zap.Logger) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Allow relative paths, but still prevent traversing above the current directory
	if strings.HasPrefix(modelPath, "..") {
		return fmt.Errorf("invalid model path: %q, cannot traverse above current directory", modelPath)
	}

	// If the path is not absolute, consider it relative to the Caddyfile's location
	var absPath string
	if !filepath.IsAbs(modelPath) {
		// Construct the absolute path based on the current working directory
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %w", err)
		}
		absPath = filepath.Join(cwd, modelPath)
	} else {
		absPath = modelPath
	}

	file, err := os.Open(absPath)
	if err != nil {
		return fmt.Errorf("failed to open model file %q: %w", absPath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("failed to close model file", zap.Error(closeErr))
		}
	}()

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

	logger.Debug("Unrecognized feature, using raw value", zap.String("feature", feature), zap.Any("value", value))
	return fmt.Sprintf("%s_%v", feature, value) // Use raw value for unknown features
}

// calculateMLScore computes the anomaly score based on normalized features.
func (m *mlModel) calculateMLScore(requestSize int64, headerCount, queryParamCount, pathSegmentCount int,
	httpMethod, userAgent, referrer string, logger *zap.Logger) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	features := []string{
		m.normalizeFeature(FeatureRequestSize, requestSize, logger),
		m.normalizeFeature(FeatureHeaderCount, headerCount, logger),
		m.normalizeFeature(FeatureQueryParamCount, queryParamCount, logger),
		m.normalizeFeature(FeaturePathSegmentCount, pathSegmentCount, logger),
		m.normalizeFeature(FeatureHTTPMethod, httpMethod, logger),
		m.normalizeFeature(FeatureUserAgent, userAgent, logger),
		m.normalizeFeature(FeatureReferrer, referrer, logger),
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

	featureValues := map[string]interface{}{
		FeatureRequestSize:      requestSize,
		FeatureHeaderCount:      headerCount,
		FeatureQueryParamCount:  queryParamCount,
		FeaturePathSegmentCount: pathSegmentCount,
		FeatureHTTPMethod:       httpMethod,
		FeatureUserAgent:        userAgent,
		FeatureReferrer:         referrer,
	}

	scores := make(map[string]float64)
	seenFeatures := make(map[string]bool)

	for featureName, value := range featureValues {
		normalizedFeature := m.normalizeFeature(featureName, value, logger)
		if mlScore, exists := m.featureScores[normalizedFeature]; exists {
			scores[normalizedFeature] = mlScore
		} else if !seenFeatures[normalizedFeature] {
			seenFeatures[normalizedFeature] = true
			scores[normalizedFeature] = defaultFeatureScore
			logger.Debug("Feature not found in model, using default score", zap.String("feature", normalizedFeature), zap.Float64("default_score", defaultFeatureScore))
		}
	}
	return scores
}

// UpdateFeatureScores adds or updates a feature score dynamically.
func (m *mlModel) UpdateFeatureScores(feature string, score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.featureScores[feature] = score
	if m.logger != nil {
		m.logger.Info("Feature score updated", zap.String("feature", feature), zap.Float64("score", score))
	}
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
