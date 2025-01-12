package caddyadf

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// AdminEndpoint implements an HTTP endpoint for managing the WAF.
type AdminEndpoint struct {
	MLWAF  *MLWAF
	logger *zap.Logger
}

// NewAdminEndpoint creates a new AdminEndpoint.
func NewAdminEndpoint(waf *MLWAF, logger *zap.Logger) *AdminEndpoint {
	return &AdminEndpoint{MLWAF: waf, logger: logger}
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (a *AdminEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	if r.URL.Path == "/ml_waf/update_model" && r.Method == http.MethodPost {
		a.handleUpdateModel(w, r)
		return nil
	} else if r.URL.Path == "/ml_waf/get_config" && r.Method == http.MethodGet {
		a.handleGetConfig(w, r)
		return nil
	}
	return next.ServeHTTP(w, r)
}

func (a *AdminEndpoint) handleUpdateModel(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	if r.Body == nil {
		a.logger.Error("empty request body")
		http.Error(w, "Please send a valid request body", http.StatusBadRequest)
		return
	}

	var updateModel struct {
		ModelPath string `json:"model_path"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateModel); err != nil {
		a.logger.Error("invalid request body", zap.Error(err))
		http.Error(w, "Please send a valid json payload", http.StatusBadRequest)
		return
	}

	if updateModel.ModelPath == "" {
		a.logger.Error("model_path not provided")
		http.Error(w, "Please specify the model path", http.StatusBadRequest)
		return
	}

	a.MLWAF.ModelPath = updateModel.ModelPath

	initializeMLModel(a.MLWAF.ModelPath, a.MLWAF.logger)

	a.logger.Info("ML model updated at runtime",
		zap.String("model_path", a.MLWAF.ModelPath),
		zap.Duration("duration", time.Since(startTime)),
	)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "ML Model updated successfully"})
}

func (a *AdminEndpoint) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	config := struct {
		AnomalyThreshold        float64 `json:"anomaly_threshold"`
		BlockingThreshold       float64 `json:"blocking_threshold"`
		ModelPath               string  `json:"model_path"`
		DynamicThresholdEnabled bool    `json:"dynamic_threshold_enabled"`
		DynamicThresholdFactor  float64 `json:"dynamic_threshold_factor"`
	}{
		AnomalyThreshold:        a.MLWAF.AnomalyThreshold,
		BlockingThreshold:       a.MLWAF.BlockingThreshold,
		ModelPath:               a.MLWAF.ModelPath,
		DynamicThresholdEnabled: a.MLWAF.DynamicThresholdEnabled,
		DynamicThresholdFactor:  a.MLWAF.DynamicThresholdFactor,
	}
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(config)

	if err != nil {
		a.logger.Error("error encoding configuration", zap.Error(err))
		http.Error(w, "error encoding configuration", http.StatusInternalServerError)
		return
	}
	a.logger.Debug("retrieved configuration",
		zap.Duration("duration", time.Since(startTime)),
	)

}

// CaddyModule returns the Caddy module information.
func (AdminEndpoint) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ml_waf_admin",
		New: func() caddy.Module { return new(AdminEndpoint) },
	}
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*AdminEndpoint)(nil)
)
