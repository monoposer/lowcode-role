package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

type entry struct {
	val bool
	exp time.Time
}

// DecisionTTL caches boolean authorization decisions keyed by revision + stable input hash.
type DecisionTTL struct {
	mu   sync.Mutex
	ttl  time.Duration
	data map[string]entry
}

func NewDecision(ttl time.Duration) *DecisionTTL {
	return &DecisionTTL{ttl: ttl, data: map[string]entry{}}
}

func (c *DecisionTTL) key(rev int64, input any) (string, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]) + ":" + strconv.FormatInt(rev, 10), nil
}

func (c *DecisionTTL) Get(rev int64, input any) (bool, bool, error) {
	k, err := c.key(rev, input)
	if err != nil {
		return false, false, err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[k]
	if !ok || now.After(e.exp) {
		return false, false, nil
	}
	return e.val, true, nil
}

func (c *DecisionTTL) Set(rev int64, input any, allow bool) error {
	k, err := c.key(rev, input)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) > 10_000 {
		c.evictExpired(time.Now())
	}
	c.data[k] = entry{val: allow, exp: time.Now().Add(c.ttl)}
	return nil
}

func (c *DecisionTTL) evictExpired(now time.Time) {
	for k, e := range c.data {
		if now.After(e.exp) {
			delete(c.data, k)
		}
	}
}
