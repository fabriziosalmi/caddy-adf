package caddyadf

import (
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// CaddyfileUnmarshaler handles unmarshaling Caddyfile configurations
type CaddyfileUnmarshaler struct {
}

// NewCaddyfileUnmarshaler creates a new CaddyfileUnmarshaler.
func NewCaddyfileUnmarshaler() *CaddyfileUnmarshaler {
	return &CaddyfileUnmarshaler{}
}

// UnmarshalCaddyfile implements the caddyfile.Unmarshaler interface.
func (cu *CaddyfileUnmarshaler) UnmarshalCaddyfile(m *MLWAF, d *caddyfile.Dispenser) error {
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
			case "enable_ml":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("parsing enable_ml: %v", err)
				}
				m.EnableML = val
			case "model_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.ModelPath = d.Val()
			case "header_redaction_list":
				m.HeaderRedactionList = []string{}
				for d.NextArg() {
					m.HeaderRedactionList = append(m.HeaderRedactionList, d.Val())
				}
			case "query_param_redaction_list":
				m.QueryParamRedactionList = []string{}
				for d.NextArg() {
					m.QueryParamRedactionList = append(m.QueryParamRedactionList, d.Val())
				}
			case "dynamic_threshold_enabled":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("parsing dynamic_threshold_enabled: %v", err)
				}
				m.DynamicThresholdEnabled = val
			case "dynamic_threshold_factor":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.ParseFloat(d.Val(), 64)
				if err != nil {
					return d.Errf("parsing dynamic_threshold_factor: %v", err)
				}
				m.DynamicThresholdFactor = val
			case "default_path_config":
				for d.NextBlock(1) {
					switch d.Val() {
					case "anomaly_threshold":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val, err := strconv.ParseFloat(d.Val(), 64)
						if err != nil {
							return d.Errf("parsing default anomaly_threshold:  %v", err)
						}
						m.DefaultPathConfig.AnomalyThreshold = val
					case "blocking_threshold":
						if !d.NextArg() {
							return d.ArgErr()
						}
						val, err := strconv.ParseFloat(d.Val(), 64)
						if err != nil {
							return d.Errf("parsing default blocking_threshold: %v", err)
						}
						m.DefaultPathConfig.BlockingThreshold = val

					default:
						return d.Errf("unrecognized option for default_path_config: %s", d.Val())
					}
				}
			case "normalization_config":
				for d.NextBlock(1) {
					if !d.NextArg() {
						return d.ArgErr()
					}
					feature := d.Val()
					if !d.NextArg() {
						return d.ArgErr()
					}
					normalizerType := d.Val()
					if normalizerType != string(LinearNormalizer) && normalizerType != string(LogNormalizer) {
						return d.Errf("unrecognized normalizer type %s", normalizerType)
					}
					if m.normalizationConfig == nil {
						m.normalizationConfig = make(map[string]string)
					}
					m.normalizationConfig[feature] = normalizerType
				}

			default:
				return d.Errf("unrecognized option: %s", d.Val())
			}
		}
	}
	return nil
}
