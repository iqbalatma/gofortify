package gofortify

import (
	"time"
)

type BlacklistDriver string

const (
	BlacklistDriverRedis  BlacklistDriver = "redis"
	BlacklistDriverMemory BlacklistDriver = "memory"
)

type Blacklist interface {
	Get(key string) any
	Set(key string, value any, expired time.Duration)
	Delete(key string)
}

var blacklistInstance Blacklist

// SetBlacklist registers the blacklist implementation to use.
// Call this once at startup after LoadJWTConfig().
func SetBlacklist(bl Blacklist) {
	blacklistInstance = bl
}

func GetBlacklist() Blacklist {
	return blacklistInstance
}

func AddBlacklistToken(jti string, duration time.Duration) {
	GetBlacklist().Set(jti, true, duration)
}
