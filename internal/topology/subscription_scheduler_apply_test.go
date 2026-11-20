package topology

import (
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
