package topology

import (
	"bytes"
	"context"
	"log"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/scanloop"
	"github.com/Resinat/Resin/internal/subscription"
)

const schedulerLookahead = 15 * time.Second

// SubscriptionScheduler manages periodic subscription updates.
type SubscriptionScheduler struct {
	subManager     *SubscriptionManager
	pool           *GlobalNodePool
	downloader     netutil.Downloader
	downloadCtx    context.Context
	cancelDownload context.CancelFunc

	// Fetcher fetches subscription data from a URL.
	// Defaults to downloader.Download; injectable for testing.
	Fetcher func(url string) ([]byte, error)

	// For persistence.
	onSubUpdated func(sub *subscription.Subscription)
	// onPullStarted is fired when a remote subscription pull starts, before
	// fetching. It is decoupled from the pull result.
	onPullStarted func(sub *subscription.Subscription)
	// onSubReenabledNode is called for each non-evicted node hash when a
	// subscription transitions from disabled to enabled.
	onSubReenabledNode func(hash node.Hash)

	// refreshing tracks in-flight pulls per subscription ID so scheduled
	// refreshes do not start a second full-pool download while one is running.
	refreshing sync.Map // subscription ID -> *atomic.Int32

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// SchedulerConfig configures the SubscriptionScheduler.
type SchedulerConfig struct {
	SubManager   *SubscriptionManager
	Pool         *GlobalNodePool
	Downloader   netutil.Downloader               // shared downloader
	Fetcher      func(url string) ([]byte, error) // optional, defaults to Downloader.Download
	OnSubUpdated func(sub *subscription.Subscription)
	// OnPullStarted is fired when a remote subscription pull starts, before
	// fetching. It is decoupled from the pull result.
	OnPullStarted func(sub *subscription.Subscription)
	// OnSubReenabledNode is fired after false->true enabled transition.
	OnSubReenabledNode func(hash node.Hash)
}

// NewSubscriptionScheduler creates a new scheduler.
func NewSubscriptionScheduler(cfg SchedulerConfig) *SubscriptionScheduler {
	downloadCtx, cancelDownload := context.WithCancel(context.Background())
	sched := &SubscriptionScheduler{
		subManager:           cfg.SubManager,
		pool:                 cfg.Pool,
		downloader:           cfg.Downloader,
		downloadCtx:          downloadCtx,
		cancelDownload:       cancelDownload,
		onSubUpdated:       cfg.OnSubUpdated,
		onPullStarted:      cfg.OnPullStarted,
		onSubReenabledNode: cfg.OnSubReenabledNode,
		stopCh:               make(chan struct{}),
	}
	if cfg.Fetcher != nil {
		sched.Fetcher = cfg.Fetcher
	} else {
		sched.Fetcher = sched.fetchViaDownloader
	}
	return sched
}

// Start launches the background scheduler goroutine.
func (s *SubscriptionScheduler) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		scanloop.Run(s.stopCh, scanloop.DefaultMinInterval, scanloop.DefaultJitterRange, s.tick)
	}()
}

// Stop signals the scheduler to stop and waits for it to finish.
func (s *SubscriptionScheduler) Stop() {
	close(s.stopCh)
	s.cancelDownload()
	s.wg.Wait()
}

// ForceRefreshAll unconditionally updates ALL enabled subscriptions, regardless
// of their next-check timestamps. Called once at startup to compensate for
// lost data from weak persistence (DESIGN.md step 8 batch 3).
// Updates run in parallel, and this method waits until all started updates exit.
func (s *SubscriptionScheduler) ForceRefreshAll() {
	select {
	case <-s.stopCh:
		return
	default:
	}

	subsToRefresh := make([]*subscription.Subscription, 0, s.subManager.Size())
	s.subManager.Range(func(id string, sub *subscription.Subscription) bool {
		select {
		case <-s.stopCh:
			return false
		default:
		}
		if sub.Enabled() {
			subsToRefresh = append(subsToRefresh, sub)
		}
		return true
	})
	s.runUpdatesWithWorkerLimit(subsToRefresh)
}

// ForceRefreshAllAsync triggers ForceRefreshAll in a background goroutine.
// The goroutine is tracked by scheduler waitgroup so Stop() waits for exit.
func (s *SubscriptionScheduler) ForceRefreshAllAsync() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.ForceRefreshAll()
	}()
}

func (s *SubscriptionScheduler) tick() {
	select {
	case <-s.stopCh:
		return
	default:
	}

	now := time.Now().UnixNano()
	dueSubs := make([]*subscription.Subscription, 0, s.subManager.Size())
	s.subManager.Range(func(id string, sub *subscription.Subscription) bool {
		select {
		case <-s.stopCh:
			return false
		default:
		}
		if !sub.Enabled() {
			return true
		}
		// Check if due: lastChecked + interval - lookahead <= now.
		if sub.LastCheckedNs.Load()+sub.UpdateIntervalNs()-int64(schedulerLookahead) <= now {
			dueSubs = append(dueSubs, sub)
		}
		return true
	})
	s.runUpdatesWithWorkerLimit(dueSubs)
}

func (s *SubscriptionScheduler) runUpdatesWithWorkerLimit(subs []*subscription.Subscription) {
	if len(subs) == 0 {
		return
	}

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if workers > len(subs) {
		workers = len(subs)
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, sub := range subs {
		select {
		case <-s.stopCh:
			wg.Wait()
			return
		default:
		}

		if s.isRefreshing(sub.ID) {
			log.Printf("[scheduler] pull for %s already in flight; skipping scheduled refresh", sub.ID)
			continue
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(sub *subscription.Subscription) {
			defer wg.Done()
			defer func() { <-sem }()
			select {
			case <-s.stopCh:
				return
			default:
			}
			s.UpdateSubscription(sub)
		}(sub)
	}
	wg.Wait()
}

func (s *SubscriptionScheduler) beginRefresh(id string) {
	counter, _ := s.refreshing.LoadOrStore(id, new(atomic.Int32))
	counter.(*atomic.Int32).Add(1)
}

func (s *SubscriptionScheduler) endRefresh(id string) {
	counter, ok := s.refreshing.Load(id)
	if !ok {
		return
	}
	if counter.(*atomic.Int32).Add(-1) <= 0 {
		s.refreshing.Delete(id)
	}
}

func (s *SubscriptionScheduler) isRefreshing(id string) bool {
	counter, ok := s.refreshing.Load(id)
	return ok && counter.(*atomic.Int32).Load() > 0
}

// UpdateSubscription fetches and parses outside the lock, then diffs and
// applies the result under WithSubLock. This keeps the lock scope narrow
// (no I/O under lock) while still preventing concurrent diff/apply races.
func (s *SubscriptionScheduler) UpdateSubscription(sub *subscription.Subscription) {
	s.beginRefresh(sub.ID)
	defer s.endRefresh(sub.ID)

	attemptStartedNs := time.Now().UnixNano()
	attemptSeq := sub.NextAttemptSeq()
	attemptURL := sub.URL()
	attemptSourceType := sub.SourceType()
	attemptContent := sub.Content()
	attemptConfigVersion := sub.ConfigVersion()

	// A pull starts here. The verified-node upload is an independent
	// operation: it starts with the pull and does not depend on its outcome.
	if attemptSourceType == subscription.SourceTypeRemote && s.onPullStarted != nil {
		s.onPullStarted(sub)
	}

	// 1. Fetch/read content (lock-free).
	var (
		body []byte
		err  error
	)
	started := time.Now()
	if attemptSourceType == subscription.SourceTypeLocal {
		body = []byte(attemptContent)
	} else {
		body, err = s.Fetcher(attemptURL)
		if err != nil {
			s.handleUpdateFailure(sub, attemptStartedNs, attemptSeq, attemptConfigVersion, "fetch", err)
			return
		}
	}
	fetchDuration := time.Since(started)

	// 2. Parse (lock-free).
	started = time.Now()
	parsed, err := subscription.ParseGeneralSubscription(body)
	if err != nil {
		s.handleUpdateFailure(sub, attemptStartedNs, attemptSeq, attemptConfigVersion, "parse", err)
		return
	}
	parseDuration := time.Since(started)

	// 3. Build refreshed managed nodes map (lock-free, pure computation).
	refreshedManagedNodes := subscription.NewManagedNodes()
	rawByHash := make(map[node.Hash][]byte)
	for _, p := range parsed {
		h := node.HashFromRawOptions(p.RawOptions)
		existing, _ := refreshedManagedNodes.LoadNode(h)
		existing.Tags = append(existing.Tags, p.Tag)
		refreshedManagedNodes.StoreNode(h, existing)
		if _, ok := rawByHash[h]; !ok {
			rawByHash[h] = p.RawOptions
		}
	}

	// 4. Diff, swap, add/remove — under lock.
	applied := false
	var (
		applyDuration  time.Duration
		addedCount     int
		keptCount      int
		unchangedCount int
		removedCount   int
	)
	sub.WithOpLock(func() {
		applyStarted := time.Now()
		defer func() { applyDuration = time.Since(applyStarted) }()
		// If refresh-input config changed while this attempt was in-flight, discard.
		if sub.ConfigVersion() != attemptConfigVersion {
			return
		}
		// Stale success guard: if a newer successful update has already landed,
		// discard this older attempt to avoid rolling state backward.
		if sub.LastAppliedSeq() > attemptSeq {
			return
		}

		old := sub.ManagedNodes()
		mergedManagedNodes := refreshedManagedNodes
		if sub.IncrementalAliveNodes() {
			mergedManagedNodes = subscription.NewManagedNodes()
			old.RangeNodes(func(h node.Hash, oldNode subscription.ManagedNode) bool {
				if oldNode.Evicted {
					mergedManagedNodes.StoreNode(h, oldNode)
					return true
				}
				if entry, ok := s.pool.GetEntry(h); ok && !shouldRemoveUnhealthyNodeForIncrementalMode(entry) {
					mergedManagedNodes.StoreNode(h, oldNode)
				}
				return true
			})
			refreshedManagedNodes.RangeNodes(func(h node.Hash, refreshedNode subscription.ManagedNode) bool {
				mergedManagedNodes.StoreNode(h, refreshedNode)
				return true
			})
		}

		// Keep hashes inherit historical eviction state so refresh will not
		// re-add previously evicted nodes back into pool.
		old.RangeNodes(func(h node.Hash, oldNode subscription.ManagedNode) bool {
			if !oldNode.Evicted {
				return true
			}
			nextNode, ok := mergedManagedNodes.LoadNode(h)
			if !ok {
				return true
			}
			nextNode.Evicted = true
			mergedManagedNodes.StoreNode(h, nextNode)
			return true
		})
		added, kept, removed := subscription.DiffHashes(old, mergedManagedNodes)
		addedCount, keptCount, removedCount = len(added), len(kept), len(removed)

		sub.SwapManagedNodes(mergedManagedNodes)

		for _, h := range added {
			managed, ok := mergedManagedNodes.LoadNode(h)
			if ok && managed.Evicted {
				continue
			}
			raw := rawByHash[h]
			if len(raw) == 0 {
				if entry, ok := s.pool.GetEntry(h); ok {
					raw = entry.RawOptions
				}
			}
			if len(raw) == 0 {
				continue
			}
			s.pool.AddNodeFromSub(h, raw, sub.ID)
		}
		for _, h := range kept {
			managed, ok := mergedManagedNodes.LoadNode(h)
			if ok && managed.Evicted {
				continue
			}
			entry, exists := s.pool.GetEntry(h)
			if !exists {
				// Recreate entries that are no longer in the pool.
				raw := rawByHash[h]
				if len(raw) > 0 {
					s.pool.AddNodeFromSub(h, raw, sub.ID)
				}
				continue
			}
			// Re-adding re-evaluates the node for every platform, which is
			// the dominant cost on large pools. Skip when neither the raw
			// options nor the subscription tags changed.
			newRaw := rawByHash[h]
			rawChanged := len(newRaw) > 0 && !bytes.Equal(newRaw, entry.RawOptions)
			oldManaged, _ := old.LoadNode(h)
			tagsChanged := !slices.Equal(oldManaged.Tags, managed.Tags)
			if !rawChanged && !tagsChanged {
				unchangedCount++
				continue
			}
			raw := newRaw
			if len(raw) == 0 {
				raw = entry.RawOptions
			}
			s.pool.AddNodeFromSub(h, raw, sub.ID)
		}
		for _, h := range removed {
			s.pool.RemoveNodeFromSub(h, sub.ID)
		}
		// 5. Update timestamps (inside lock, using current time).
		now := time.Now().UnixNano()
		sub.LastCheckedNs.Store(now)
		sub.LastUpdatedNs.Store(now)
		sub.MarkAppliedAttempt(attemptSeq)
		sub.SetLastError("")
		applied = true
	})
	if !applied {
		log.Printf("[scheduler] stale success ignored for %s", sub.ID)
		return
	}
	log.Printf(
		"[scheduler] refreshed %s: fetch=%s parse=%s apply=%s bytes=%d parsed=%d added=%d kept=%d kept_unchanged=%d removed=%d",
		sub.ID, fetchDuration, parseDuration, applyDuration,
		len(body), len(parsed), addedCount, keptCount, unchangedCount, removedCount,
	)

	if s.onSubUpdated != nil {
		s.onSubUpdated(sub)
	}
}

// handleUpdateFailure applies a fetch/parse failure to subscription state.
// It ignores stale failures from an outdated attempt (config-version guard +
// LastUpdatedNs stale-success guard).

func shouldRemoveUnhealthyNodeForIncrementalMode(entry *node.NodeEntry) bool {
	if entry == nil {
		return false
	}
	return entry.IsCircuitOpen() || (!entry.HasOutbound() && entry.GetLastError() != "")
}

func (s *SubscriptionScheduler) handleUpdateFailure(
	sub *subscription.Subscription,
	attemptStartedNs int64,
	attemptSeq int64,
	attemptConfigVersion int64,
	stage string,
	err error,
) {
	applied := false
	sub.WithOpLock(func() {
		// If refresh-input config changed while this attempt was in-flight, discard.
		if sub.ConfigVersion() != attemptConfigVersion {
			return
		}
		if sub.LastAppliedSeq() > attemptSeq {
			return
		}
		now := time.Now().UnixNano()
		sub.LastCheckedNs.Store(now)
		sub.SetLastError(err.Error())
		applied = true
	})
	if !applied {
		log.Printf("[scheduler] stale %s failure ignored for %s: %v", stage, sub.ID, err)
		return
	}

	log.Printf("[scheduler] %s %s failed: %v", stage, sub.ID, err)
	if s.onSubUpdated != nil {
		s.onSubUpdated(sub)
	}
}

// SetSubscriptionEnabled updates the enabled flag and rebuilds all platform
// routable views. Disabling a subscription makes its nodes invisible to
// platform tag-regex matching; enabling makes them visible again.
func (s *SubscriptionScheduler) SetSubscriptionEnabled(sub *subscription.Subscription, enabled bool) {
	wasEnabled := false
	var candidateHashes []node.Hash
	wasDisabled := make(map[node.Hash]struct{})
	sub.WithOpLock(func() {
		wasEnabled = sub.Enabled()

		if !wasEnabled && enabled {
			sub.ManagedNodes().RangeNodes(func(h node.Hash, managed subscription.ManagedNode) bool {
				if managed.Evicted {
					return true
				}
				candidateHashes = append(candidateHashes, h)
				if s.pool != nil && s.pool.IsNodeDisabled(h) {
					wasDisabled[h] = struct{}{}
				}
				return true
			})
		}

		sub.SetEnabled(enabled)
	})
	// Rebuild all platform views so they pick up the visibility change.
	s.pool.RebuildAllPlatforms()

	// On re-enable, immediately re-check node outbound/probe state for nodes
	// that actually transitioned from disabled -> enabled.
	if !wasEnabled && enabled && s.onSubReenabledNode != nil {
		for _, h := range candidateHashes {
			if _, ok := wasDisabled[h]; !ok {
				continue
			}
			if s.pool.IsNodeDisabled(h) {
				continue
			}
			s.onSubReenabledNode(h)
		}
	}

	if s.onSubUpdated != nil {
		s.onSubUpdated(sub)
	}
}

// RecheckNodes schedules follow-up work after an already-published config
// change. Callers must release the subscription operation lock first.
func (s *SubscriptionScheduler) RecheckNodes(hashes []node.Hash) {
	if s.onSubReenabledNode == nil {
		return
	}
	for _, hash := range hashes {
		if !s.pool.IsNodeDisabled(hash) {
			s.onSubReenabledNode(hash)
		}
	}
}

// RenameSubscription updates the subscription name and re-triggers platform
// re-evaluation for all managed nodes (since tags include the sub name).
func (s *SubscriptionScheduler) RenameSubscription(sub *subscription.Subscription, newName string) {
	sub.WithOpLock(func() {
		sub.SetName(newName)
		// Re-add all managed hashes to trigger platform re-filter.
		sub.ManagedNodes().RangeNodes(func(h node.Hash, managed subscription.ManagedNode) bool {
			if managed.Evicted {
				return true
			}
			entry, ok := s.pool.GetEntry(h)
			if ok {
				s.pool.AddNodeFromSub(h, entry.RawOptions, sub.ID)
			}
			return true
		})
	})
}

func (s *SubscriptionScheduler) fetchViaDownloader(url string) ([]byte, error) {
	return s.downloader.Download(s.downloadCtx, url)
}
