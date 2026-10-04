// Package library scans the audiobook folder tree, groups audio files into
// books, derives metadata/chapters/covers, and keeps a persistent index with
// a probe cache so restarts and periodic rescans are cheap.
package library

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"math"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vburenin/bookbeam/server/internal/fsutil"
	"github.com/vburenin/bookbeam/server/internal/media"
)

// ProbeFunc reads an audio file's metadata (media.ProbeFile in production).
// It returns an error wrapping media.ErrNotAudio for files whose content is
// not audio; those are left out of the index.
type ProbeFunc func(path string, opts media.Options) (*media.Info, error)

// Options configure a Library.
type Options struct {
	// Root is the audiobook library. It is never written to.
	Root string
	// StateDir receives library.json and the covers/ cache.
	StateDir string
	// FFprobe enables the prober's ffprobe fallback.
	FFprobe bool
	// Probe defaults to media.ProbeFile.
	Probe ProbeFunc
	// Workers bounds concurrent probes; defaults to min(8, NumCPU).
	Workers int
	Logger  *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// ScanEvent reports a completed scan to subscribers.
type ScanEvent struct {
	Version string
	Changed bool  // the index version changed
	Manual  bool  // requested through RequestRescan
	Err     error // non-nil if the scan failed or was refused (the old index stays)
}

var (
	// ErrLibraryEmpty refuses a scan that found no audio at all while the
	// index has books: the library is most likely not mounted (an empty
	// mount point, a NAS share that dropped). The previous index stays and
	// the library is checked again soon; a forced rescan (RescanOptions)
	// accepts an empty library.
	ErrLibraryEmpty = errors.New("library: no audio files found; keeping the previous index (is the library mounted?)")
	// ErrLibraryShrank refuses an automatic scan that lost most of the
	// indexed files at once (a sub-share not mounted?). The previous index
	// stays until a re-check shortly after confirms the loss, or until a
	// manual rescan.
	ErrLibraryShrank = errors.New("library: most indexed files are gone; keeping the previous index until a re-check confirms it")
	// ErrForbidden reports a file that resolves into BookBeam's own state or
	// the legacy v1 secret files, which are never served.
	ErrForbidden = errors.New("library: file resolves into BookBeam's state")
)

// cacheSchema versions library.json; bump it when probe results or the
// grouping rules change meaning, so stale caches are re-probed.
const cacheSchema = 3 // 3: tags in legacy code pages (Windows-1251) are decoded

const (
	// missingGrace is how long the probe results (and extracted covers) of
	// files that vanished are kept, so that a share that drops out for a
	// while, or a folder renamed back, needs no re-probing.
	missingGrace = 7 * 24 * time.Hour
	// recheckDelay is how soon a library that looks unavailable (a refused
	// or failed scan) is scanned again; the delay doubles while the problem
	// lasts, up to the scan interval.
	recheckDelay = time.Minute
)

// cacheFile is the persisted form of the library (library.json).
type cacheFile struct {
	Schema    int                    `json:"schema"`
	ScannedAt int64                  `json:"scannedAt"`
	Files     map[string]*probeEntry `json:"files"`
	Images    map[string]*imageEntry `json:"images,omitempty"`
	Added     map[string]int64       `json:"added"`
	Books     []*Book                `json:"books"`
}

// probeEntry caches one file's probe result, keyed by rel path and
// validated by size and mtime.
type probeEntry struct {
	Size    int64       `json:"size"`
	ModTime int64       `json:"mtime"`
	Info    *media.Info `json:"info,omitempty"`
	Err     string      `json:"err,omitempty"`
	// Retry marks a failure that may be transient (an I/O error, a
	// timeout): the file is probed again by every scan until it succeeds.
	Retry bool `json:"retry,omitempty"`
	// NotAudio marks a file whose content is not audio; it is not indexed.
	NotAudio bool `json:"notAudio,omitempty"`
	// Cover is the extracted embedded picture inside the covers cache.
	Cover string `json:"cover,omitempty"`
	// CoverErr remembers why the embedded picture could not be extracted.
	CoverErr string `json:"coverErr,omitempty"`
	// Missing is when the file was first found gone (ms since epoch), 0
	// while it exists. The entry is dropped missingGrace later.
	Missing int64 `json:"missing,omitempty"`
}

// Library owns the current index and the scanning machinery.
type Library struct {
	opts         Options
	log          *slog.Logger
	root         string
	cachePath    string
	coversDir    string
	recheckDelay time.Duration

	mu    sync.RWMutex
	index *Index
	ready bool

	deny atomic.Pointer[denyList] // refreshed by every scan

	// Scanner state, guarded by scanMu (one scan at a time).
	scanMu     sync.Mutex
	files      map[string]*probeEntry
	images     map[string]*imageEntry
	added      map[string]int64
	hadCache   bool
	shrinkSeen bool // the previous automatic scan was refused as a shrink

	scanning      atomic.Bool
	rescanPending atomic.Bool
	forceRescan   atomic.Bool
	rescanCh      chan struct{}

	subsMu sync.Mutex
	subs   []func(ScanEvent)
}

// Open prepares a library and loads the persisted index, if any, so it can
// be served before the first scan finishes.
func Open(opts Options) (*Library, error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("library root: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("library root %s is not a directory", root)
	}
	if opts.Probe == nil {
		opts.Probe = media.ProbeFile
	}
	if opts.Workers <= 0 {
		opts.Workers = min(8, runtime.NumCPU())
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	l := &Library{
		opts:         opts,
		log:          opts.Logger,
		root:         root,
		cachePath:    filepath.Join(opts.StateDir, "library.json"),
		coversDir:    filepath.Join(opts.StateDir, "covers"),
		recheckDelay: recheckDelay,
		index:        NewIndex(nil, 0),
		files:        map[string]*probeEntry{},
		images:       map[string]*imageEntry{},
		added:        map[string]int64{},
		rescanCh:     make(chan struct{}, 1),
	}
	l.loadCache()
	return l, nil
}

func (l *Library) loadCache() {
	var cf cacheFile
	err := fsutil.ReadJSON(l.cachePath, &cf)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		l.log.Warn("ignoring unreadable library cache; rescanning", "err", err)
		return
	}
	l.hadCache = true
	if cf.Added != nil {
		l.added = cf.Added
	}
	if cf.Schema == cacheSchema {
		if cf.Files != nil {
			l.files = cf.Files
		}
		if cf.Images != nil {
			l.images = cf.Images
		}
	} else {
		// The saved index is still served until the first scan replaces it.
		l.log.Info("library cache format changed; files will be re-probed")
	}
	l.index = NewIndex(cf.Books, cf.ScannedAt)
	l.ready = true
	l.log.Info("loaded library index", "books", len(cf.Books), "version", l.index.Version)
}

// Index returns the current snapshot (never nil; empty before any scan).
func (l *Library) Index() *Index {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.index
}

// Ready reports whether an index has been loaded or scanned.
func (l *Library) Ready() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.ready
}

// Scanning reports whether a scan is running or a rescan is queued.
func (l *Library) Scanning() bool { return l.scanning.Load() || l.rescanPending.Load() }

// Subscribe registers fn to be called after every scan attempt.
func (l *Library) Subscribe(fn func(ScanEvent)) {
	l.subsMu.Lock()
	defer l.subsMu.Unlock()
	l.subs = append(l.subs, fn)
}

// RescanOptions tune a requested rescan.
type RescanOptions struct {
	// Force publishes the result even when it finds no audio at all while
	// the index has books (a library emptied on purpose). Without it such a
	// scan keeps the previous index and reports ErrLibraryEmpty.
	Force bool
}

// RequestRescan queues a full rescan (failed probes are retried) to be run
// by Run. Requests made while one is queued are coalesced; a forced request
// forces the coalesced scan.
func (l *Library) RequestRescan(opts ...RescanOptions) {
	for _, o := range opts {
		if o.Force {
			l.forceRescan.Store(true)
		}
	}
	l.rescanPending.Store(true)
	select {
	case l.rescanCh <- struct{}{}:
	default:
	}
}

// Run scans once immediately, then every interval (if > 0) and whenever a
// rescan is requested, until ctx is cancelled. After a failed or refused
// scan (the library looks unmounted) it checks again within minutes rather
// than waiting for the next interval.
func (l *Library) Run(ctx context.Context, interval time.Duration) {
	var tick <-chan time.Time
	if interval > 0 {
		t := time.NewTicker(interval)
		defer t.Stop()
		tick = t.C
	}
	var (
		recheck <-chan time.Time
		delay   time.Duration
	)
	after := func(err error) {
		if err == nil {
			recheck, delay = nil, 0
			return
		}
		delay = max(2*delay, l.recheckDelay)
		if interval > 0 {
			delay = min(delay, max(interval, l.recheckDelay))
		}
		recheck = time.After(delay)
	}

	// Failures that may be transient are retried by every scan; definitive
	// ones only by a manual rescan.
	after(l.runScan(ctx, ScanOptions{}))
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			after(l.runScan(ctx, ScanOptions{}))
		case <-recheck:
			after(l.runScan(ctx, ScanOptions{}))
		case <-l.rescanCh:
			after(l.runScan(ctx, ScanOptions{RetryFailed: true, Manual: true, Force: l.forceRescan.Swap(false)}))
		}
	}
}

func (l *Library) runScan(ctx context.Context, opts ScanOptions) error {
	if opts.Manual {
		l.rescanPending.Store(false)
	}
	changed, err := l.ScanWith(ctx, opts)
	if ctx.Err() != nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrLibraryShrank):
		l.log.Warn("library scan not published", "err", err)
	case err != nil:
		l.log.Error("library scan failed", "err", err)
	}
	ev := ScanEvent{Version: l.Index().Version, Changed: changed, Manual: opts.Manual, Err: err}
	l.subsMu.Lock()
	subs := append([]func(ScanEvent){}, l.subs...)
	l.subsMu.Unlock()
	for _, fn := range subs {
		fn(ev)
	}
	return err
}

// AbsPath converts a library-relative path to an absolute one.
func (l *Library) AbsPath(rel string) string {
	return filepath.Join(l.root, filepath.FromSlash(rel))
}

// CoverPath returns the image file backing a cover.
func (l *Library) CoverPath(c *Cover) string {
	if c.Kind == CoverEmbedded {
		return filepath.Join(l.coversDir, filepath.Base(c.Source))
	}
	return l.AbsPath(c.Source)
}

// ResolveFile returns the real (symlink-free) path of a library file for
// serving, or ErrForbidden when it resolves into BookBeam's state or the
// legacy v1 secret files: a symlink swapped after the scan cannot expose
// them. Resolution errors (fs.ErrNotExist...) are returned as they are.
// Open the returned path, not AbsPath(rel).
func (l *Library) ResolveFile(rel string) (string, error) {
	real, err := filepath.EvalSymlinks(l.AbsPath(rel))
	if err != nil {
		return "", err
	}
	if l.denied().contains(real) {
		return "", ErrForbidden
	}
	return real, nil
}

// ResolveCover is ResolveFile for a cover: a file cover must pass the same
// checks, and an embedded one must resolve to a file directly inside the
// covers cache.
func (l *Library) ResolveCover(c *Cover) (string, error) {
	if c.Kind != CoverEmbedded {
		return l.ResolveFile(c.Source)
	}
	real, err := filepath.EvalSymlinks(l.CoverPath(c))
	if err != nil {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(l.coversDir)
	if err != nil {
		return "", err
	}
	if filepath.Dir(real) != dir {
		return "", ErrForbidden
	}
	return real, nil
}

// denied returns the deny list of the last scan, computing it if needed.
func (l *Library) denied() denyList {
	if d := l.deny.Load(); d != nil {
		return *d
	}
	d := l.denyList()
	l.deny.Store(&d)
	return d
}

// denyList lists the real paths whose files must never be indexed or
// served: the state directory, and the legacy v1 files in the library root
// (session_secret, state/, audiobooks.json). Both the plain and the
// symlink-resolved forms are listed.
func (l *Library) denyList() denyList {
	root := l.root
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	forms := func(p string) denyList {
		var d denyList
		if abs, err := filepath.Abs(p); err == nil {
			d = append(d, abs)
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			d = append(d, real)
		}
		return d
	}
	var d denyList
	if s := l.opts.StateDir; s != "" {
		state := forms(s)
		if state.contains(root) || state.contains(l.root) {
			// Denying it would hide the whole library.
			l.log.Error("the state directory contains the library; set -state elsewhere", "state", s)
		} else {
			d = append(d, state...)
		}
	}
	for _, name := range []string{"session_secret", "state", "audiobooks.json"} {
		d = append(d, forms(filepath.Join(root, name))...)
	}
	return d
}

// probe calls the configured prober, converting panics into errors so one
// malformed file can never take the server down.
func (l *Library) probe(path string, o media.Options) (info *media.Info, err error) {
	defer func() {
		if r := recover(); r != nil {
			info, err = nil, fmt.Errorf("prober panic: %v", r)
		}
	}()
	info, err = l.opts.Probe(path, o)
	if err == nil && info == nil {
		err = errors.New("prober returned no information")
	}
	return info, err
}

// scanner holds per-scan state.
type scanner struct {
	lib        *Library
	entries    map[string]*probeEntry // probe results of the files seen
	images     map[string]*imageEntry // image files examined
	cacheDirty bool
}

// ScanOptions tune one scan.
type ScanOptions struct {
	// RetryFailed re-probes files whose previous probe failed for good.
	// (Failures that may be transient are retried by every scan.)
	RetryFailed bool
	// Manual marks a scan someone asked for: it publishes a library that
	// lost most of its files at once without waiting for a re-check.
	Manual bool
	// Force publishes whatever the scan finds, even no audio at all while
	// the index has books.
	Force bool
}

// Scan walks the library, probes new or changed files and publishes a new
// index; see ScanWith. retryFailed re-probes files whose previous probe
// failed. It reports whether the index version changed.
func (l *Library) Scan(ctx context.Context, retryFailed bool) (bool, error) {
	return l.ScanWith(ctx, ScanOptions{RetryFailed: retryFailed})
}

// ScanWith walks the library, probes new or changed files and publishes a
// new index, reporting whether its version changed. A scan that makes the
// library look unavailable is refused with ErrLibraryEmpty or
// ErrLibraryShrank (see ScanOptions): the previous index stays.
func (l *Library) ScanWith(ctx context.Context, opts ScanOptions) (bool, error) {
	l.scanMu.Lock()
	defer l.scanMu.Unlock()
	l.scanning.Store(true)
	defer l.scanning.Store(false)
	began := time.Now()

	deny := l.denyList()
	l.deny.Store(&deny)
	w := &walker{ctx: ctx, root: l.root, log: l.log, deny: deny}
	tree, err := w.walk()
	if err != nil {
		return false, err
	}
	var audio []fileEntry
	collectAudio(tree, &audio)

	s := &scanner{lib: l, images: map[string]*imageEntry{}}
	probed, err := s.probeAll(ctx, audio, opts.RetryFailed)
	if err != nil {
		return false, err
	}
	dropAudio(tree, func(f fileEntry) bool {
		e := s.entries[f.Rel]
		return e == nil || !e.NotAudio
	})

	specs := groupBooks(tree, func(rel string) *media.Info {
		if e := s.entries[rel]; e != nil {
			return e.Info
		}
		return nil
	})
	now := l.opts.Now()
	books := make([]*Book, 0, len(specs))
	metas := make([]bookMeta, 0, len(specs))
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		b, meta := s.buildBook(spec)
		at, seen := l.added[b.ID]
		if !seen {
			// On the very first scan every book is "new"; ordering them by
			// file age gives a meaningful "recently added" list.
			at = now.UnixMilli()
			if !l.hadCache {
				at = newestMTime(spec.Files)
			}
			l.added[b.ID] = at
			s.cacheDirty = true
		}
		b.AddedAt = at
		books = append(books, b)
		metas = append(metas, meta)
	}
	disambiguateTitles(books, metas)
	books = l.keepUnreadable(books, w.failed)
	sort.Slice(books, func(i, j int) bool { return NaturalLess(books[i].Path, books[j].Path) })

	idx := NewIndex(books, now.UnixMilli())
	if err := l.checkPlausible(idx, opts); err != nil {
		// Keep the probing work for the re-check. Nothing ages: the files
		// are unavailable rather than gone.
		maps.Copy(l.files, s.entries)
		return false, err
	}
	l.mu.Lock()
	changed := !l.ready || idx.Version != l.index.Version
	if !changed {
		idx = l.index.withScannedAt(now.UnixMilli())
	}
	l.index = idx
	l.ready = true
	l.mu.Unlock()

	if l.mergeEntries(s.entries, now) {
		s.cacheDirty = true
	}
	if len(s.images) != len(l.images) {
		s.cacheDirty = true
	}
	l.images = s.images
	if changed || probed > 0 || s.cacheDirty || !l.hadCache {
		if err := l.saveCache(idx); err != nil {
			l.log.Error("saving library cache", "err", err)
		} else {
			l.hadCache = true
		}
	}
	l.pruneCovers()
	l.log.Info("library scanned", "books", len(books), "files", len(audio), "probed", probed,
		"changed", changed, "version", idx.Version, "took", time.Since(began).Round(time.Millisecond))
	return changed, nil
}

// checkPlausible refuses a scan result that makes a library with books look
// unavailable rather than changed: no audio at all (ErrLibraryEmpty, unless
// forced), or, for automatic scans, more than half of the indexed files gone
// (ErrLibraryShrank) the first time it is seen. Files that merely moved
// (same name, size and mtime elsewhere) do not count as gone.
func (l *Library) checkPlausible(idx *Index, opts ScanOptions) error {
	old := l.Index()
	if opts.Force || !l.Ready() {
		l.shrinkSeen = false
		return nil
	}
	total, lost := 0, 0
	for _, b := range old.Books {
		for _, t := range b.Tracks {
			total++
			if _, _, ok := idx.TrackByPath(t.Path); ok {
				continue
			}
			moved := slices.ContainsFunc(idx.TracksByBaseAndSize(path.Base(t.Path), t.Size), func(r TrackRef) bool {
				return r.Book.Tracks[r.Track].ModTime == t.ModTime
			})
			if !moved {
				lost++
			}
		}
	}
	if total == 0 {
		return nil
	}
	if len(idx.byTrack) == 0 {
		return ErrLibraryEmpty
	}
	if lost*2 > total && !opts.Manual && !l.shrinkSeen {
		l.shrinkSeen = true
		return fmt.Errorf("%w (%d of %d files)", ErrLibraryShrank, lost, total)
	}
	l.shrinkSeen = false
	return nil
}

// keepUnreadable keeps the current index's books that have files under
// paths this scan could not read (a sub-folder failing with EIO or EACCES
// during a NAS hiccup) instead of dropping them. Newly built books that
// overlap a kept one (a disc book seen without its unreadable disc) give
// way to it.
func (l *Library) keepUnreadable(books []*Book, failed []string) []*Book {
	if len(failed) == 0 {
		return books
	}
	under := func(p string) bool {
		return slices.ContainsFunc(failed, func(f string) bool { return p == f || strings.HasPrefix(p, f+"/") })
	}
	var kept []*Book
	keptIDs, keptTracks := map[string]bool{}, map[string]bool{}
	for _, b := range l.Index().Books {
		if !slices.ContainsFunc(b.Tracks, func(t Track) bool { return under(t.Path) }) {
			continue
		}
		kept = append(kept, b)
		keptIDs[b.ID] = true
		for _, t := range b.Tracks {
			keptTracks[t.Path] = true
		}
	}
	if len(kept) == 0 {
		return books
	}
	books = slices.DeleteFunc(books, func(b *Book) bool {
		return keptIDs[b.ID] || slices.ContainsFunc(b.Tracks, func(t Track) bool { return keptTracks[t.Path] })
	})
	return append(books, kept...)
}

// mergeEntries makes seen (the probe results of the files this scan found)
// the probe cache, keeping the entries of files it did not find for
// missingGrace so that they need neither probing nor cover extraction when
// they come back (a share that dropped out, a folder renamed back). It
// reports whether the cache changed beyond seen's own entries.
func (l *Library) mergeEntries(seen map[string]*probeEntry, now time.Time) (dirty bool) {
	nowMs := now.UnixMilli()
	for rel, e := range l.files {
		if _, ok := seen[rel]; ok {
			continue
		}
		if e.Missing == 0 {
			e.Missing = nowMs
			dirty = true
		}
		if nowMs-e.Missing > missingGrace.Milliseconds() {
			dirty = true
			continue
		}
		seen[rel] = e
	}
	l.files = seen
	return dirty
}

func (l *Library) saveCache(idx *Index) error {
	b, err := json.Marshal(cacheFile{
		Schema:    cacheSchema,
		ScannedAt: idx.ScannedAt,
		Files:     l.files,
		Images:    l.images,
		Added:     l.added,
		Books:     idx.Books,
	})
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(l.cachePath, b, 0o644)
}

func collectAudio(d *dirNode, out *[]fileEntry) {
	*out = append(*out, d.Audio...)
	for _, sub := range d.Dirs {
		collectAudio(sub, out)
	}
}

func newestMTime(files []fileEntry) int64 {
	var newest int64
	for _, f := range files {
		newest = max(newest, f.ModTime)
	}
	return newest / int64(time.Millisecond)
}

// probeAll fills s.entries for every audio file, reusing cache entries for
// unchanged (or moved) files and probing the rest with a worker pool. It
// returns the number of files probed.
func (s *scanner) probeAll(ctx context.Context, files []fileEntry, retryFailed bool) (int, error) {
	l := s.lib
	s.entries = make(map[string]*probeEntry, len(files))
	var todo []fileEntry
	for _, f := range files {
		e := l.files[f.Rel]
		if e != nil && e.Size == f.Size && e.ModTime == f.ModTime && (e.Err == "" || (!retryFailed && !e.Retry)) {
			if e.Missing != 0 {
				e.Missing = 0
				s.cacheDirty = true
			}
			s.entries[f.Rel] = e
			continue
		}
		todo = append(todo, f)
	}
	todo = s.reuseMoved(todo)
	if len(todo) == 0 {
		return 0, nil
	}
	l.log.Info("probing audio files", "count", len(todo), "workers", l.opts.Workers)

	jobs := make(chan fileEntry)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for range l.opts.Workers {
		wg.Go(func() {
			for f := range jobs {
				e := &probeEntry{Size: f.Size, ModTime: f.ModTime}
				info, err := l.probe(l.AbsPath(f.Rel), media.Options{FFprobe: l.opts.FFprobe})
				switch {
				case errors.Is(err, media.ErrNotAudio):
					e.NotAudio = true
					l.log.Warn("skipping a file whose content is not audio", "path", f.Rel)
				case err != nil:
					e.Err = err.Error()
					e.Retry = media.IsTransient(err)
					l.log.Warn("cannot read audio metadata; duration will be discovered by the player",
						"path", f.Rel, "err", err, "retry", e.Retry)
				default:
					info.Picture = nil
					e.Info = info
				}
				mu.Lock()
				s.entries[f.Rel] = e
				mu.Unlock()
			}
		})
	}
feed:
	for _, f := range todo {
		select {
		case jobs <- f:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return len(todo), ctx.Err()
}

// reuseMoved gives files that moved the probe results cached under their
// old path: a file in todo whose name, size and mtime match the entry of a
// path this scan did not see (renaming or moving a folder keeps its files'
// mtimes) needs no probing. It returns the files still to probe.
func (s *scanner) reuseMoved(todo []fileEntry) []fileEntry {
	if len(todo) == 0 {
		return todo
	}
	type identity struct {
		name        string
		size, mtime int64
	}
	gone := map[identity]*probeEntry{}
	for rel, e := range s.lib.files {
		if _, seen := s.entries[rel]; !seen && e.Err == "" {
			gone[identity{path.Base(rel), e.Size, e.ModTime}] = e
		}
	}
	if len(gone) == 0 {
		return todo
	}
	rest := todo[:0:0]
	for _, f := range todo {
		if e := gone[identity{f.Name, f.Size, f.ModTime}]; e != nil {
			moved := *e
			moved.Missing = 0
			s.entries[f.Rel] = &moved
			s.cacheDirty = true
			continue
		}
		rest = append(rest, f)
	}
	return rest
}

// buildBook turns a grouping decision into a Book.
func (s *scanner) buildBook(spec bookSpec) (*Book, bookMeta) {
	b := &Book{ID: BookID(spec.Rel), Path: spec.Rel, Folder: parentDir(spec.Rel)}
	infos := make([]*media.Info, len(spec.Files))
	for i, f := range spec.Files {
		if e := s.entries[f.Rel]; e != nil {
			infos[i] = e.Info
		}
	}
	titles := trackTitles(spec.Files, infos)
	labelDiscTracks(spec, titles)
	b.Tracks = make([]Track, len(spec.Files))
	var start float64
	for i, f := range spec.Files {
		format := audioFormats[strings.ToLower(filepath.Ext(f.Name))]
		var dur float64
		if in := infos[i]; in != nil {
			dur = roundMs(in.Duration)
			if in.Format != "" {
				format = in.Format
			}
		}
		b.Tracks[i] = Track{
			Title:    titles[i],
			Path:     f.Rel,
			Format:   format,
			Duration: dur,
			Start:    roundMs(start),
			Size:     f.Size,
			ModTime:  f.ModTime,

			Fingerprint: TrackFingerprint(f.Rel, f.Size, f.ModTime),
		}
		start += dur
		b.Size += f.Size
	}
	b.Duration = roundMs(start)
	b.Chapters = buildChapters(b.Tracks, infos)
	meta := applyMetadata(b, spec, infos, s.lib.root)
	b.Cover = s.pickCover(spec)
	return b, meta
}

// buildChapters lists a book's chapters: a track's embedded chapters when
// it has at least two, otherwise the track itself.
func buildChapters(tracks []Track, infos []*media.Info) []Chapter {
	out := make([]Chapter, 0, len(tracks))
	for i, t := range tracks {
		var emb []media.Chapter
		if infos[i] != nil {
			emb = infos[i].Chapters
		}
		if len(emb) < 2 {
			out = append(out, Chapter{Title: t.Title, Track: i, End: t.Duration, BookStart: t.Start})
			continue
		}
		for j, c := range emb {
			end := c.End
			if end <= c.Start {
				if j+1 < len(emb) {
					end = emb[j+1].Start
				} else {
					end = max(t.Duration, c.Start)
				}
			}
			title := clean(c.Title)
			if title == "" {
				title = fmt.Sprintf("Chapter %d", j+1)
			}
			out = append(out, Chapter{
				Title:     title,
				Track:     i,
				Start:     roundMs(c.Start),
				End:       roundMs(end),
				BookStart: roundMs(t.Start + c.Start),
			})
		}
	}
	return out
}

func parentDir(rel string) string {
	if d := path.Dir(rel); d != "." && d != "/" {
		return d
	}
	return ""
}

// roundMs rounds seconds to millisecond precision.
func roundMs(sec float64) float64 {
	if math.IsNaN(sec) || math.IsInf(sec, 0) || sec < 0 {
		return 0
	}
	return math.Round(sec*1000) / 1000
}
