package revision

import "sync/atomic"

// Holder tracks the latest published policy revision for cache invalidation.
type Holder struct {
	v atomic.Int64
}

func (h *Holder) Set(rev int64) {
	h.v.Store(rev)
}

func (h *Holder) Current() int64 {
	return h.v.Load()
}
