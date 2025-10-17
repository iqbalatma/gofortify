package blacklist

import (
	"github.com/iqbalatma/gofortify/config"
	"time"
)

type Blacklist interface {
	Get(key string) any
	Set(key string, value any, expired time.Duration)
	Delete(key string)
}

// GetBlacklist TODO :
func GetBlacklist() Blacklist {
	return NewRedisBlacklist(config.RDB)
}

func AddBlacklistToken(jti string, duration time.Duration) {
	GetBlacklist().Set(jti, true, duration)
}
