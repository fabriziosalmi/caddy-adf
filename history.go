package caddyadf

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// RequestHistoryManager manages request history.
type RequestHistoryManager struct {
	requestHistoryShards map[string]map[string][]requestRecord
	historyMutex         sync.RWMutex
	numShards            int
	historyWindow        time.Duration
	maxHistoryEntries    int
	logger               *zap.Logger
}

// NewRequestHistoryManager creates a new RequestHistoryManager.
func NewRequestHistoryManager(numShards int, historyWindow time.Duration, maxHistoryEntries int, logger *zap.Logger) *RequestHistoryManager {
	return &RequestHistoryManager{
		requestHistoryShards: make(map[string]map[string][]requestRecord),
		numShards:            numShards,
		historyWindow:        historyWindow,
		maxHistoryEntries:    maxHistoryEntries,
		logger:               logger,
	}
}

// getShard returns the shard number for a given client IP
func (rhm *RequestHistoryManager) getShard(clientIP string) string {
	hash := 0
	for _, char := range clientIP {
		hash = (hash*31 + int(char)) % rhm.numShards
	}
	return string(rune(hash % rhm.numShards))
}

// getRequestHistory retrieves the request history for a given client IP and shard
func (rhm *RequestHistoryManager) GetRequestHistory(clientIP string, shard string) []requestRecord {
	rhm.historyMutex.RLock()
	defer rhm.historyMutex.RUnlock()

	if _, ok := rhm.requestHistoryShards[clientIP]; !ok {
		return nil
	}
	return rhm.requestHistoryShards[clientIP][shard]
}

// updateRequestHistory updates the request history for a given client IP and shard
func (rhm *RequestHistoryManager) UpdateRequestHistory(clientIP string, shard string, anomalyScore float64) {
	rhm.historyMutex.Lock()
	defer rhm.historyMutex.Unlock()
	record := requestRecord{Timestamp: time.Now(), AnomalyScore: anomalyScore}

	if _, ok := rhm.requestHistoryShards[clientIP]; !ok {
		rhm.requestHistoryShards[clientIP] = make(map[string][]requestRecord)
	}
	history := rhm.requestHistoryShards[clientIP][shard]
	history = append(history, record)

	prunedHistory := rhm.pruneRequestHistory(history)
	rhm.requestHistoryShards[clientIP][shard] = prunedHistory

	rhm.logger.Debug("updated request history",
		zap.String("client_ip", clientIP),
		zap.String("shard", shard),
		zap.Float64("anomaly_score", anomalyScore),
		zap.Int("history_size", len(prunedHistory)),
	)
}

// pruneRequestHistory prunes the request history to remove old entries
func (rhm *RequestHistoryManager) pruneRequestHistory(history []requestRecord) []requestRecord {
	cutoff := time.Now().Add(-rhm.historyWindow)
	prunedHistory := make([]requestRecord, 0, len(history))
	for _, rec := range history {
		if rec.Timestamp.After(cutoff) {
			prunedHistory = append(prunedHistory, rec)
		}
	}
	if len(prunedHistory) > rhm.maxHistoryEntries {
		prunedHistory = prunedHistory[len(prunedHistory)-rhm.maxHistoryEntries:]
	}
	return prunedHistory
}
