package blacklist

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisBlacklist struct {
	RedisClient *redis.Client
	Context     context.Context
}

func (rb *RedisBlacklist) Get(key string) any {
	val, err := rb.RedisClient.Get(rb.Context, key).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	} else if err != nil {
		panic(err)
	}
	return val
}

func (rb *RedisBlacklist) Set(key string, value any, expired time.Duration) {
	err := rb.RedisClient.Set(rb.Context, key, value, expired).Err()
	if err != nil {
		panic(err)
	}
}

func (rb *RedisBlacklist) Delete(key string) {
}

func NewRedisBlacklist(RedisClient *redis.Client) *RedisBlacklist {
	return &RedisBlacklist{
		RedisClient: RedisClient,
		Context:     context.Background(),
	}
}
