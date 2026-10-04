package auth

import (
	"sync"
	"time"
)

// limitRule says: after max failures within window, block for lockout.
type limitRule struct {
	max     int
	window  time.Duration
	lockout time.Duration
}

var (
	userRule = limitRule{max: 10, window: 15 * time.Minute, lockout: time.Minute}
	ipRule   = limitRule{max: 30, window: 15 * time.Minute, lockout: 5 * time.Minute}
)

type bucket struct {
	failures     []time.Time // within the rule's window, oldest first
	blockedUntil time.Time
}

// prune drops failures that left the window.
func (b *bucket) prune(now time.Time, window time.Duration) {
	cut := 0
	for cut < len(b.failures) && now.Sub(b.failures[cut]) >= window {
		cut++
	}
	b.failures = b.failures[cut:]
}

// rateLimiter throttles password guessing per username and per client IP.
type rateLimiter struct {
	mu        sync.Mutex
	users     map[string]*bucket
	ips       map[string]*bucket
	lastSweep time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{users: map[string]*bucket{}, ips: map[string]*bucket{}}
}

// check returns how long the caller must wait, or 0 when a login attempt is
// allowed. user may be "" (unknown usernames are only limited per IP so
// arbitrary names cannot grow the table).
func (l *rateLimiter) check(user, ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	var wait time.Duration
	if b := l.users[user]; user != "" && b != nil && now.Before(b.blockedUntil) {
		wait = b.blockedUntil.Sub(now)
	}
	if b := l.ips[ip]; b != nil && now.Before(b.blockedUntil) {
		wait = max(wait, b.blockedUntil.Sub(now))
	}
	return wait
}

// fail records a failed attempt.
func (l *rateLimiter) fail(user, ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if user != "" {
		record(l.users, user, userRule, now)
	}
	record(l.ips, ip, ipRule, now)
	if now.Sub(l.lastSweep) > time.Minute {
		l.sweep(now)
	}
}

// succeed clears the username's failure history.
func (l *rateLimiter) succeed(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.users, user)
}

func record(m map[string]*bucket, key string, rule limitRule, now time.Time) {
	b := m[key]
	if b == nil {
		b = &bucket{}
		m[key] = b
	}
	b.prune(now, rule.window)
	b.failures = append(b.failures, now)
	if len(b.failures) >= rule.max {
		b.blockedUntil = now.Add(rule.lockout)
	}
}

// sweep forgets buckets with no recent failures and no active block.
func (l *rateLimiter) sweep(now time.Time) {
	l.lastSweep = now
	for _, t := range []struct {
		m    map[string]*bucket
		rule limitRule
	}{{l.users, userRule}, {l.ips, ipRule}} {
		for k, b := range t.m {
			b.prune(now, t.rule.window)
			if len(b.failures) == 0 && !now.Before(b.blockedUntil) {
				delete(t.m, k)
			}
		}
	}
}
