package config

import (
	"strconv"

	"github.com/redis/go-redis/v9"
)

var RDB *redis.Client

func ConnectRedis() {
	db, err := strconv.Atoi(Config.RedisDatabase)

	if err != nil {
		return
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     Config.RedisHost + ":" + Config.RedisPort,
		Password: Config.RedisPassword,
		DB:       db,
	})

	RDB = rdb
}
