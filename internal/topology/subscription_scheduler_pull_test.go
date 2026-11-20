package topology

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/subscription"
)

func TestScheduler_OnPullStartedFiresAtPullStart(t *testing.T) {
	subMgr := NewSubscriptionManager()
	sub := subscription.NewSubscription("s1", "TestSub", "http://example.com", true, false)
	sub.SetFetchConfig(sub.URL(), int64(time.Hour))
	subMgr.Register(sub)
	pool := newTestPool(subMgr)

	var pullStarted atomic.Int32
	sched := NewSubscriptionScheduler(SchedulerConfig{
		SubManager: subMgr,
		Pool:       pool,
		Fetcher:    makeMockFetcher(nil, errors.New("boom")),
		OnPullStarted: func(*subscription.Subscription) {
			pullStarted.Add(1)
		},
	})

	// A pull that ultimately fails still fired the trigger: the upload is
	// independent from the pull result.
	sched.UpdateSubscription(sub)
	if got := pullStarted.Load(); got != 1 {
		t.Fatalf("pull-started callbacks after failed pull = %d, want 1", got)
	}

	sched.Fetcher = makeMockFetcher(makeSubscriptionJSON(
		`{"type":"shadowsocks","tag":"us-1","server":"1.1.1.1","server_port":443}`,
	), nil)
	sched.UpdateSubscription(sub)
	if got := pullStarted.Load(); got != 2 {
		t.Fatalf("pull-started callbacks after successful pull = %d, want 2", got)
	}
}

func TestScheduler_OnPullStartedSkipsLocalSubscriptions(t *testing.T) {
	subMgr := NewSubscriptionManager()
	sub := subscription.NewSubscription("s1", "LocalSub", "", false, false)
	sub.SetSourceType(subscription.SourceTypeLocal)
	sub.SetContent(string(makeSubscriptionJSON(
		`{"type":"shadowsocks","tag":"us-1","server":"1.1.1.1","server_port":443}`,
	)))
	subMgr.Register(sub)
	pool := newTestPool(subMgr)

	var pullStarted atomic.Int32
	sched := NewSubscriptionScheduler(SchedulerConfig{
		SubManager: subMgr,
		Pool:       pool,
		Fetcher:    makeMockFetcher(nil, errors.New("must not fetch local subscriptions")),
		OnPullStarted: func(*subscription.Subscription) {
			pullStarted.Add(1)
		},
	})

	sched.UpdateSubscription(sub)
	if got := pullStarted.Load(); got != 0 {
		t.Fatalf("pull-started callbacks for local subscription = %d, want 0", got)
	}
}
