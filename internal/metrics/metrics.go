package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RoleRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "role_requests_total",
		Help: "Role policy evaluations",
	}, []string{"result"})

	RoleLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "role_eval_seconds",
		Help:    "End-to-end /v1/authorize handler latency",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
	}, []string{"cache"})

	OPALatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "role_opa_seconds",
		Help:    "OPA HTTP evaluation latency",
		Buckets: prometheus.ExponentialBuckets(0.00005, 2, 18),
	})

	CacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "role_cache_hits_total",
		Help: "Decision cache hits",
	})
	CacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "role_cache_misses_total",
		Help: "Decision cache misses",
	})
)
