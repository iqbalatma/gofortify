package gofortify

import "github.com/iqbalatma/gofortify/config"

func GetAccessTTL() int {
	return config.Config.AccessTokenTTL
}

func GetRefreshTTL() int {
	return config.Config.RefreshTokenTTL
}
