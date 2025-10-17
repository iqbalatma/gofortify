package config

import (
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

type JWTConfig struct {
	SigningMethod   string
	JWTSecretKey    string
	AccessTokenTTL  int
	RefreshTokenTTL int
	RedisHost       string
	RedisPort       string
	RedisPassword   string
	RedisDatabase   string
	IncidentKey     string
}

var Config *JWTConfig

func LoadJWTConfig() {
	accessTokenTTL, err := strconv.Atoi(os.Getenv("JWT_ACCESS_TOKEN_TTL"))
	if err != nil {
		accessTokenTTL = 30
	}

	refreshTokenTTL, err := strconv.Atoi(os.Getenv("JWT_REFRESH_TOKEN_TTL"))
	if err != nil {
		refreshTokenTTL = 10080
	}

	Config = &JWTConfig{
		SigningMethod:   os.Getenv("JWT_SIGNING_METHOD"),
		JWTSecretKey:    os.Getenv("JWT_SECRET_KEY"),
		AccessTokenTTL:  accessTokenTTL,
		RefreshTokenTTL: refreshTokenTTL,
		RedisHost:       os.Getenv("JWT_REDIS_HOST"),
		RedisPort:       os.Getenv("JWT_REDIS_PORT"),
		RedisPassword:   os.Getenv("JWT_REDIS_PASSWORD"),
		RedisDatabase:   os.Getenv("JWT_REDIS_DB"),
		IncidentKey:     os.Getenv("JWT_BLACKLIST_INCIDENT_TIME_KEY"),
	}
}

func getAvailableSigningMethods() map[string]jwt.SigningMethod {
	return map[string]jwt.SigningMethod{
		"HS256": jwt.SigningMethodHS256,
		"HS384": jwt.SigningMethodHS384,
		"HS512": jwt.SigningMethodHS512,
		"ES512": jwt.SigningMethodES512,
		"ES384": jwt.SigningMethodES384,
		"ES256": jwt.SigningMethodES256,
		"EdDSA": jwt.SigningMethodEdDSA,
		"PS256": jwt.SigningMethodPS256,
		"PS512": jwt.SigningMethodPS512,
		"PS384": jwt.SigningMethodPS384,
		"RS256": jwt.SigningMethodRS256,
		"RS512": jwt.SigningMethodRS512,
		"RS384": jwt.SigningMethodRS384,
	}
}
func GetSigningMethod() jwt.SigningMethod {
	return getAvailableSigningMethods()[Config.SigningMethod]
}
