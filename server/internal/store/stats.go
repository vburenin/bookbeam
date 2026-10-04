package store

import (
	"time"

	"github.com/vburenin/bookbeam/server/internal/library"
)

// statsDays is how many days of per-day listening history are kept.
const statsDays = 400

const dateLayout = "2006-01-02"

// localDate converts a server instant to the client's calendar date.
// tzOffset follows JS Date.getTimezoneOffset(): minutes to add to local
// time to get UTC (e.g. 420 for UTC-7).
func localDate(now time.Time, tzOffset int) time.Time {
	local := now.UTC().Add(-time.Duration(tzOffset) * time.Minute)
	y, m, d := local.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// add records listening time on a local date and prunes old days.
func (st *Stats) add(day time.Time, secs float64) {
	st.Days[day.Format(dateLayout)] += secs
	st.Total += secs
	cutoff := day.AddDate(0, 0, -(statsDays - 1)).Format(dateLayout)
	for k := range st.Days {
		if k < cutoff {
			delete(st.Days, k)
		}
	}
}

// DayStat is one day of listening.
type DayStat struct {
	Date    string  `json:"date"`
	Seconds float64 `json:"seconds"`
}

// StatsView is the response of GET api/stats.
type StatsView struct {
	Today           float64   `json:"today"`
	Week            []DayStat `json:"week"` // 7 days, oldest first, ending today
	Total           float64   `json:"total"`
	Streak          int       `json:"streak"` // consecutive days with listening
	BooksFinished   int       `json:"booksFinished"`
	BooksInProgress int       `json:"booksInProgress"`
}

// Stats summarises a user's listening relative to the client's local day.
// The streak counts back from today, or from yesterday when nothing has
// been played yet today (so the streak isn't "lost" in the morning).
func (s *Store) Stats(name string, idx *library.Index, tzOffset int) (StatsView, error) {
	if tzOffset < -maxTZOffset || tzOffset > maxTZOffset {
		tzOffset = 0
	}
	var v StatsView
	err := s.withUser(name, idx, func(u *user) error {
		days := u.data.Stats.Days
		today := localDate(s.now(), tzOffset)
		v.Today = days[today.Format(dateLayout)]
		v.Week = make([]DayStat, 7)
		for i := range 7 {
			d := today.AddDate(0, 0, i-6).Format(dateLayout)
			v.Week[i] = DayStat{Date: d, Seconds: days[d]}
		}
		v.Total = u.data.Stats.Total
		day := today
		if v.Today == 0 {
			day = day.AddDate(0, 0, -1)
		}
		for days[day.Format(dateLayout)] > 0 {
			v.Streak++
			day = day.AddDate(0, 0, -1)
		}
		for _, p := range u.data.Progress {
			if p.Finished {
				v.BooksFinished++
			} else {
				v.BooksInProgress++
			}
		}
		return nil
	})
	return v, err
}
