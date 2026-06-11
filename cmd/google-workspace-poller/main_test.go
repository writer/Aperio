package main

import (
	"context"
	"testing"
	"time"
)

func TestWaitForWakeWorkWaitsForDynamicWork(t *testing.T) {
	tracker := newWakeTracker()
	finishFirst := tracker.start()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	returned := make(chan struct{})
	go func() {
		waitForWakeWork(ctx, tracker, 5*time.Millisecond, 500*time.Millisecond)
		close(returned)
	}()

	time.Sleep(20 * time.Millisecond)
	finishSecond := tracker.start()
	finishFirst()

	select {
	case <-returned:
		t.Fatal("waitForWakeWork returned while a later wake-up was still running")
	case <-time.After(20 * time.Millisecond):
	}

	finishSecond()

	select {
	case <-returned:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waitForWakeWork did not return after all wake-ups finished")
	}
}

func TestWaitForWakeWorkReturnsAfterQuietWindowWhenIdle(t *testing.T) {
	tracker := newWakeTracker()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	startedAt := time.Now()
	waitForWakeWork(ctx, tracker, 10*time.Millisecond, 500*time.Millisecond)
	if elapsed := time.Since(startedAt); elapsed < 10*time.Millisecond {
		t.Fatalf("waitForWakeWork returned before quiet window elapsed: %s", elapsed)
	}
}
