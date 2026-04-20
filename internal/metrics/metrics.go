package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	AuthzRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "authz_requests_total",
		Help: "Authorization evaluations",
	}, []string{"result"})

	AuthzLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "authz_eval_seconds",
		Help:    "End-to-end authorize handler latency",
		Buckets: prometheus.ExponentialBuckets(0.0001, 2, 16),
	}, []string{"cache"})

	OPALatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "authz_opa_seconds",
		Help:    "OPA HTTP evaluation latency",
		Buckets: prometheus.ExponentialBuckets(0.00005, 2, 18),
	})

	CacheHits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "authz_cache_hits_total",
		Help: "Decision cache hits",
	})
	CacheMisses = promauto.NewCounter(prometheus.CounterOpts{
		Name: "authz_cache_misses_total",
		Help: "Decision cache misses",
	})
)
