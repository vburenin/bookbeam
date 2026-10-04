package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Pairing statuses reported to the polling device.
const (
	PairPending  = "pending"
	PairApproved = "approved"
	PairDenied   = "denied"
	PairExpired  = "expired"
)

const (
	pairCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	pairCodeLen      = 6
	pairTTL          = 10 * time.Minute
	// pairRedeemGrace keeps an approval redeemable for a little while even
	// if it was granted just before the code expired.
	pairRedeemGrace = 2 * time.Minute
	maxPendingPerIP = 5
)

var (
	// ErrTooManyPairings is returned when an IP already has too many codes.
	ErrTooManyPairings = errors.New("too many pending pairing codes")
	// ErrPairingNotFound is returned for unknown or expired codes.
	ErrPairingNotFound = errors.New("pairing code not found or expired")
	// ErrPairingUsed is returned when a code was already approved or denied.
	ErrPairingUsed = errors.New("pairing code already used")
)

// PairRequest is a device waiting to be signed in by an approver.
type PairRequest struct {
	Code       string `json:"code"`
	DeviceName string `json:"deviceName"`
	UA         string `json:"ua"`
	IP         string `json:"ip"`
	CreatedAt  int64  `json:"createdAt"` // ms
	ExpiresAt  int64  `json:"expiresAt"` // ms
	Status     string `json:"status"`

	pollToken   string
	user        string // approver, once approved
	sessionName string // name chosen by the approver
}

// Approval is what a redeemed pairing grants: a session for User named Name.
type Approval struct {
	User string
	Name string
}

// pairing tracks in-flight device pairings in memory (they live minutes).
type pairing struct {
	mu     sync.Mutex
	byCode map[string]*PairRequest
	byPoll map[string]*PairRequest
}

func newPairing() *pairing {
	return &pairing{byCode: map[string]*PairRequest{}, byPoll: map[string]*PairRequest{}}
}

// NormalizePairCode upper-cases a user-entered code and drops "-" and spaces.
func NormalizePairCode(code string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(code)))
}

// start registers a new pairing request and returns it with its poll token.
func (p *pairing) start(deviceName, ua, ip string, now time.Time) (PairRequest, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)

	pending := 0
	for _, r := range p.byCode {
		if r.IP == ip && r.Status == PairPending {
			pending++
		}
	}
	if pending >= maxPendingPerIP {
		return PairRequest{}, "", ErrTooManyPairings
	}

	var code string
	for {
		c, err := randomCode()
		if err != nil {
			return PairRequest{}, "", err
		}
		if _, taken := p.byCode[c]; !taken {
			code = c
			break
		}
	}
	var tok [16]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return PairRequest{}, "", err
	}
	r := &PairRequest{
		Code:       code,
		DeviceName: deviceName,
		UA:         ua,
		IP:         ip,
		CreatedAt:  now.UnixMilli(),
		ExpiresAt:  now.Add(pairTTL).UnixMilli(),
		Status:     PairPending,
		pollToken:  hex.EncodeToString(tok[:]),
	}
	p.byCode[code] = r
	p.byPoll[r.pollToken] = r
	return *r, r.pollToken, nil
}

// lookup returns the live request for a code.
func (p *pairing) lookup(code string, now time.Time) (PairRequest, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	r, ok := p.byCode[NormalizePairCode(code)]
	if !ok {
		return PairRequest{}, ErrPairingNotFound
	}
	return *r, nil
}

// decide approves (user != "") or denies a pending request.
func (p *pairing) decide(code, user, name string, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	r, ok := p.byCode[NormalizePairCode(code)]
	if !ok {
		return ErrPairingNotFound
	}
	if r.Status != PairPending {
		return ErrPairingUsed
	}
	if user == "" {
		r.Status = PairDenied
		return nil
	}
	r.Status = PairApproved
	r.user = user
	r.sessionName = name
	if grace := now.Add(pairRedeemGrace).UnixMilli(); r.ExpiresAt < grace {
		r.ExpiresAt = grace
	}
	return nil
}

// poll reports a request's status. An approval is handed out exactly once:
// the request is consumed by the poll that returns it. Denials are consumed
// too, so unknown, redeemed and timed-out tokens all read as expired.
func (p *pairing) poll(pollToken string, now time.Time) (string, Approval) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	r, ok := p.byPoll[pollToken]
	if !ok {
		return PairExpired, Approval{}
	}
	switch r.Status {
	case PairApproved:
		p.removeLocked(r)
		return PairApproved, Approval{User: r.user, Name: r.sessionName}
	case PairDenied:
		p.removeLocked(r)
		return PairDenied, Approval{}
	default:
		return PairPending, Approval{}
	}
}

func (p *pairing) expireLocked(now time.Time) {
	ms := now.UnixMilli()
	for _, r := range p.byCode {
		if ms >= r.ExpiresAt {
			p.removeLocked(r)
		}
	}
}

func (p *pairing) removeLocked(r *PairRequest) {
	delete(p.byCode, r.Code)
	delete(p.byPoll, r.pollToken)
}

func randomCode() (string, error) {
	var b strings.Builder
	n := big.NewInt(int64(len(pairCodeAlphabet)))
	for range pairCodeLen {
		i, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", err
		}
		b.WriteByte(pairCodeAlphabet[i.Int64()])
	}
	return b.String(), nil
}
