package caddyadf

import (
	"math"
)

// NormalizerType represents the type of normalization to apply.
type NormalizerType string

const (
	LinearNormalizer NormalizerType = "linear"
	LogNormalizer    NormalizerType = "log"
)

// RequestNormalizer is responsible for normalizing values.
type RequestNormalizer struct {
	normalizers map[string]NormalizerType
}

// NewRequestNormalizer creates a new RequestNormalizer
func NewRequestNormalizer() *RequestNormalizer {
	return &RequestNormalizer{
		normalizers: make(map[string]NormalizerType),
	}
}

func (rn *RequestNormalizer) SetNormalizer(feature string, normalizerType NormalizerType) {
	rn.normalizers[feature] = normalizerType
}

func (rn *RequestNormalizer) getNormalizer(feature string) NormalizerType {
	if val, ok := rn.normalizers[feature]; ok {
		return val
	}
	return LinearNormalizer // Default Normalizer
}

// NormalizeValue normalizes a value based on a min and max range
func (rn *RequestNormalizer) NormalizeValue(feature string, value float64, min float64, max float64) float64 {

	normalizerType := rn.getNormalizer(feature)

	switch normalizerType {
	case LinearNormalizer:
		return rn.linearNormalizeValue(value, min, max)
	case LogNormalizer:
		return rn.logNormalizeValue(value, min, max)
	default:
		return rn.linearNormalizeValue(value, min, max)
	}

}

func (rn *RequestNormalizer) linearNormalizeValue(value float64, min float64, max float64) float64 {
	if min == max {
		return 0.0
	}
	if value < min {
		return (min - value) / (min + 1)
	} else if value > max {
		return (value - max) / (max + 1)
	}
	return 0.0
}

func (rn *RequestNormalizer) logNormalizeValue(value float64, min float64, max float64) float64 {
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
