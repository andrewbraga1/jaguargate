package telemetry

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// MetricsCollector provides lock-free atomic counters for Prometheus / OpenTelemetry scraping.
type MetricsCollector struct {
	reqClean         atomic.Uint64
	reqSanitized     atomic.Uint64
	reqShadowFlagged atomic.Uint64
	reqBlocked       atomic.Uint64
	prunedToolsTotal atomic.Uint64
	latencySumUs     atomic.Uint64
	latencyCount     atomic.Uint64

	codeCounters sync.Map // map[string]*atomic.Uint64
}

// NewMetricsCollector creates an initialized lock-free metrics registry.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

// RecordRequest atomically records request outcome, flag codes, pruned tool count, and latency in microseconds.
func (m *MetricsCollector) RecordRequest(status string, codes []string, prunedTools int, latencyUs int64) {
	if m == nil {
		return
	}

	switch status {
	case "SANITIZED":
		m.reqSanitized.Add(1)
	case "SHADOW_FLAGGED":
		m.reqShadowFlagged.Add(1)
	case "BLOCKED":
		m.reqBlocked.Add(1)
	default:
		m.reqClean.Add(1)
	}

	if prunedTools > 0 {
		m.prunedToolsTotal.Add(uint64(prunedTools))
	}

	if latencyUs >= 0 {
		m.latencySumUs.Add(uint64(latencyUs))
		m.latencyCount.Add(1)
	}

	for _, c := range codes {
		if c == "" {
			continue
		}
		val, ok := m.codeCounters.Load(c)
		if !ok {
			newCounter := &atomic.Uint64{}
			val, _ = m.codeCounters.LoadOrStore(c, newCounter)
		}
		val.(*atomic.Uint64).Add(1)
	}
}

// Handler returns an http.Handler serving standard Prometheus / OpenMetrics text format.
func (m *MetricsCollector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(m.RenderPrometheusText()))
	})
}

// RenderPrometheusText formats all atomic metrics into OpenMetrics / Prometheus exposition text.
func (m *MetricsCollector) RenderPrometheusText() string {
	var b strings.Builder
	b.Grow(1024)

	b.WriteString("# HELP jaguargate_requests_total Total AI/MCP requests inspected by JaguarGate.\n")
	b.WriteString("# TYPE jaguargate_requests_total counter\n")
	writeMetricLine(&b, "jaguargate_requests_total", "status", "CLEAN", m.reqClean.Load())
	writeMetricLine(&b, "jaguargate_requests_total", "status", "SANITIZED", m.reqSanitized.Load())
	writeMetricLine(&b, "jaguargate_requests_total", "status", "SHADOW_FLAGGED", m.reqShadowFlagged.Load())
	writeMetricLine(&b, "jaguargate_requests_total", "status", "BLOCKED", m.reqBlocked.Load())

	b.WriteString("# HELP jaguargate_pruned_tools_total Total unauthorized or looping tool calls surgically pruned.\n")
	b.WriteString("# TYPE jaguargate_pruned_tools_total counter\n")
	b.WriteString("jaguargate_pruned_tools_total ")
	b.WriteString(strconv.FormatUint(m.prunedToolsTotal.Load(), 10))
	b.WriteByte('\n')

	b.WriteString("# HELP jaguargate_latency_microseconds_sum Cumulative gateway inspection overhead in microseconds.\n")
	b.WriteString("# TYPE jaguargate_latency_microseconds_sum counter\n")
	b.WriteString("jaguargate_latency_microseconds_sum ")
	b.WriteString(strconv.FormatUint(m.latencySumUs.Load(), 10))
	b.WriteByte('\n')

	b.WriteString("# HELP jaguargate_latency_microseconds_count Total requests measured for latency.\n")
	b.WriteString("# TYPE jaguargate_latency_microseconds_count counter\n")
	b.WriteString("jaguargate_latency_microseconds_count ")
	b.WriteString(strconv.FormatUint(m.latencyCount.Load(), 10))
	b.WriteByte('\n')

	type codeEntry struct {
		code  string
		count uint64
	}
	var entries []codeEntry
	m.codeCounters.Range(func(key, value any) bool {
		k, ok1 := key.(string)
		v, ok2 := value.(*atomic.Uint64)
		if ok1 && ok2 {
			entries = append(entries, codeEntry{code: k, count: v.Load()})
		}
		return true
	})
	sort.Slice(entries, func(i, j int) bool { return entries[i].code < entries[j].code })

	b.WriteString("# HELP jaguargate_flag_triggers_total Total security and governance flags triggered by code.\n")
	b.WriteString("# TYPE jaguargate_flag_triggers_total counter\n")
	for _, e := range entries {
		writeMetricLine(&b, "jaguargate_flag_triggers_total", "code", e.code, e.count)
	}

	return b.String()
}

func writeMetricLine(b *strings.Builder, metric, labelKey, labelVal string, val uint64) {
	b.WriteString(metric)
	b.WriteString(`{`)
	b.WriteString(labelKey)
	b.WriteString(`="`)
	b.WriteString(labelVal)
	b.WriteString(`"} `)
	b.WriteString(strconv.FormatUint(val, 10))
	b.WriteByte('\n')
}
