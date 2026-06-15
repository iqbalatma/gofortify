package gofortify

import (
	"sync"
	"time"
)

type memoryBlacklistEntry struct {
	value     any
	expiresAt time.Time
	noExpires bool
}
type MemoryBlacklist struct {
	store map[string]memoryBlacklistEntry
	rwm   sync.RWMutex
}

func (mb *MemoryBlacklist) Get(key string) any {
	mb.rwm.RLock()
	defer mb.rwm.RUnlock()

	entry, oke := mb.store[key]
	if !oke {
		return nil
	}

	if !entry.noExpires && time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.value
}

func (mb *MemoryBlacklist) Set(key string, value any, expired time.Duration) {
	mb.rwm.Lock()
	defer mb.rwm.Unlock()
	mb.store[key] = memoryBlacklistEntry{
		value:     value,
		expiresAt: time.Now().Add(expired),
		noExpires: expired == 0,
	}
}

func (mb *MemoryBlacklist) Delete(key string) {
	mb.rwm.Lock()
	defer mb.rwm.Unlock()
	delete(mb.store, key)
}

func (mb *MemoryBlacklist) startCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			mb.rwm.Lock()
			for key, entry := range mb.store {
				if !entry.noExpires && time.Now().After(entry.expiresAt) {
					delete(mb.store, key)
				}
			}
			mb.rwm.Unlock()
		}
	}()
}

func NewMemoryBlacklist() *MemoryBlacklist {
	mb := &MemoryBlacklist{
		store: make(map[string]memoryBlacklistEntry),
	}

	mb.startCleanup(5 * time.Minute)
	return mb
}
