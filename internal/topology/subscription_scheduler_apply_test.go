package topology

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/subscription"
)

func TestScheduler_RefreshSkipsUnchangedKeptNodes(t *testing.T) {
	subMgr := NewSubscriptionManager()
	sub := subscription.NewSubscription("s1", "TestSub", "http://example.com", true, false)
	sub.SetFetchConfig(sub.URL(), int64(time.Hour))
	subMgr.Register(sub)

	var subNodeChanges atomic.Int32
	pool := NewGlobalNodePool(PoolConfig{
		SubLookup:              subMgr.Lookup,
		MaxLatencyTableEntries: 8,
		MaxConsecutiveFailures: func() int { return 3 },
		OnSubNodeChanged: func(string, node.Hash, bool) {
			subNodeChanges.Add(1)
		},
	})

	body := makeSubscriptionJSON(
		`{"type":"shadowsocks","tag":"a","server":"1.1.1.1","server_port":443}`,
		`{"type":"shadowsocks","tag":"b","server":"2.2.2.2","server_port":443}`,
	)
	sched := NewSubscriptionScheduler(SchedulerConfig{
		SubManager: subMgr,
		Pool:       pool,
		Fetcher:    makeMockFetcher(body, nil),
	})

	sched.UpdateSubscription(sub)
	if got := subNodeChanges.Load(); got != 2 {
		t.Fatalf("initial refresh sub-node changes = %d, want 2", got)
	}
	subNodeChanges.Store(0)

	// Re-applying an identical subscription must not re-add kept nodes.
	sched.UpdateSubscription(sub)
	if got := subNodeChanges.Load(); got != 0 {
		t.Fatalf("unchanged refresh sub-node changes = %d, want 0", got)
	}
	if pool.Size() != 2 {
		t.Fatalf("pool size = %d, want 2", pool.Size())
	}
}

func TestScheduler_ScheduledRefreshSkipsInFlightPull(t *testing.T) {
	subMgr := NewSubscriptionManager()
	sub := subscription.NewSubscription("s1", "TestSub", "http://example.com", true, false)
	sub.SetFetchConfig(sub.URL(), int64(time.Hour))
	subMgr.Register(sub)
	pool := newTestPool(subMgr)

	started := make(chan struct{})
	release := make(chan struct{})
	var fetches atomic.Int32
	fetcher := func(string) ([]byte, error) {
		if fetches.Add(1) == 1 {
			close(started)
		}
		<-release
		return makeSubscriptionJSON(
			`{"type":"shadowsocks","tag":"a","server":"1.1.1.1","server_port":443}`,
		), nil
	}
	sched := NewSubscriptionScheduler(SchedulerConfig{
		SubManager: subMgr,
		Pool:       pool,
		Fetcher:    fetcher,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		sched.UpdateSubscription(sub)
	}()
	<-started

	// A scheduled round (tick or startup force-refresh) must not start a
	// second full download while the subscription is already pulling.
	sched.runUpdatesWithWorkerLimit([]*subscription.Subscription{sub})
	if got := fetches.Load(); got != 1 {
		t.Fatalf("scheduled pulls while one was in flight = %d, want 1", got)
	}

	close(release)
	<-done
}

func TestScheduler_RefreshStatsSnapshot(t *testing.T) {
	subMgr := NewSubscriptionManager()
	sub := subscription.NewSubscription("s1", "StatsSub", "http://example.com", true, false)
	sub.SetFetchConfig(sub.URL(), int64(time.Hour))
	subMgr.Register(sub)
	pool := newTestPool(subMgr)

	body := makeSubscriptionJSON(
		`{"type":"shadowsocks","tag":"a","server":"1.1.1.1","server_port":443}`,
	)
	sched := NewSubscriptionScheduler(SchedulerConfig{
		SubManager: subMgr,
		Pool:       pool,
		Fetcher:    makeMockFetcher(body, nil),
	})

	sched.UpdateSubscription(sub)
	snapshot := sched.RefreshStatsSnapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot length = %d, want 1", len(snapshot))
	}
	stat := snapshot[0]
	if stat.InFlight || stat.StartedAt == "" || stat.FinishedAt == "" {
		t.Fatalf("unexpected timing state: %+v", stat)
	}
	if stat.Bytes == 0 || stat.Parsed != 1 || stat.Added != 1 || stat.Kept != 0 {
		t.Fatalf("unexpected counters: %+v", stat)
	}
	if stat.Error != "" {
		t.Fatalf("unexpected error: %q", stat.Error)
	}

	sched.Fetcher = makeMockFetcher(nil, errors.New("boom"))
	sched.UpdateSubscription(sub)
	snapshot = sched.RefreshStatsSnapshot()
	if len(snapshot) != 1 || !strings.Contains(snapshot[0].Error, "fetch:") {
		t.Fatalf("failure stats = %+v", snapshot)
	}
	if snapshot[0].InFlight {
		t.Fatalf("in-flight after failure: %+v", snapshot[0])
	}
}

func TestScheduler_RefreshStatsShowsInFlight(t *testing.T) {
	subMgr := NewSubscriptionManager()
	sub := subscription.NewSubscription("s1", "StatsSub", "http://example.com", true, false)
	sub.SetFetchConfig(sub.URL(), int64(time.Hour))
	subMgr.Register(sub)
	pool := newTestPool(subMgr)

	release := make(chan struct{})
	started := make(chan struct{})
	var once atomic.Bool
	fetcher := func(string) ([]byte, error) {
		if once.CompareAndSwap(false, true) {
			close(started)
		}
		<-release
		return makeSubscriptionJSON(
			`{"type":"shadowsocks","tag":"a","server":"1.1.1.1","server_port":443}`,
		), nil
	}
	sched := NewSubscriptionScheduler(SchedulerConfig{
		SubManager: subMgr,
		Pool:       pool,
		Fetcher:    fetcher,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		sched.UpdateSubscription(sub)
	}()
	<-started

	snapshot := sched.RefreshStatsSnapshot()
	if len(snapshot) != 1 || !snapshot[0].InFlight || snapshot[0].StartedAt == "" {
		t.Fatalf("in-flight snapshot = %+v", snapshot)
	}

	close(release)
	<-done
	if snapshot := sched.RefreshStatsSnapshot(); snapshot[0].InFlight {
		t.Fatalf("still in flight after completion: %+v", snapshot[0])
	}
}
