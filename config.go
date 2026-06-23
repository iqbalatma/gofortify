package gofortify

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

type JWTConfig struct {
	IssuerServer    string
	SigningMethod   string
	JWTSecretKey    string
	JWTPublicKey    string
	AccessTokenTTL  int
	RefreshTokenTTL int
	RedisHost       string
	RedisPort       string
	RedisPassword   string
	RedisDatabase   string
	IncidentKey     string
	BlacklistDriver BlacklistDriver
}

var (
	Config     *JWTConfig
	configOnce sync.Once
)

func LoadJWTConfig() {
	configOnce.Do(func() {
		accessTokenTTL, err := strconv.Atoi(os.Getenv("JWT_ACCESS_TOKEN_TTL"))
		if err != nil {
			accessTokenTTL = 30
		}

		refreshTokenTTL, err := strconv.Atoi(os.Getenv("JWT_REFRESH_TOKEN_TTL"))
		if err != nil {
			refreshTokenTTL = 10080
		}

		issuerServer := os.Getenv("JWT_ISSUER_SERVER")
		if issuerServer == "" {
			issuerServer = "http://localhost:8080"
		}

		signingMethod := os.Getenv("JWT_SIGNING_METHOD")
		if signingMethod == "" {
			signingMethod = "HS256"
		}

		incidentKey := os.Getenv("JWT_BLACKLIST_INCIDENT_TIME_KEY")
		if incidentKey == "" {
			incidentKey = "jwt_incident"
		}
		Config = &JWTConfig{
			IssuerServer:    issuerServer,
			SigningMethod:   signingMethod,
			JWTSecretKey:    os.Getenv("JWT_SECRET_KEY"),
			JWTPublicKey:    os.Getenv("JWT_PUBLIC_KEY"),
			AccessTokenTTL:  accessTokenTTL,
			RefreshTokenTTL: refreshTokenTTL,
			RedisHost:       os.Getenv("JWT_REDIS_HOST"),
			RedisPort:       os.Getenv("JWT_REDIS_PORT"),
			RedisPassword:   os.Getenv("JWT_REDIS_PASSWORD"),
			RedisDatabase:   os.Getenv("JWT_REDIS_DB"),
			IncidentKey:     os.Getenv("JWT_BLACKLIST_INCIDENT_TIME_KEY"),
			BlacklistDriver: BlacklistDriver(os.Getenv("JWT_BLACKLIST_DRIVER")),
		}

		if Config.BlacklistDriver == BlacklistDriverRedis {
			ConnectRedis()
			SetBlacklist(NewRedisBlacklist(RDB))
		} else if Config.BlacklistDriver == BlacklistDriverMemory {
			SetBlacklist(NewMemoryBlacklist())
		}
	})
}

func getAvailableSigningMethods() map[string]jwt.SigningMethod {
	return map[string]jwt.SigningMethod{
		"HS256": jwt.SigningMethodHS256,
		"HS384": jwt.SigningMethodHS384,
		"HS512": jwt.SigningMethodHS512,
		"ES256": jwt.SigningMethodES256,
		"ES384": jwt.SigningMethodES384,
		"ES512": jwt.SigningMethodES512,
		"EdDSA": jwt.SigningMethodEdDSA,
		"PS256": jwt.SigningMethodPS256,
		"PS384": jwt.SigningMethodPS384,
		"PS512": jwt.SigningMethodPS512,
		"RS256": jwt.SigningMethodRS256,
		"RS384": jwt.SigningMethodRS384,
		"RS512": jwt.SigningMethodRS512,
	}
}

func GetSigningMethod() jwt.SigningMethod {
	return getAvailableSigningMethods()[Config.SigningMethod]
}

// GetSigningKey returns the correct key type for signing based on the configured algorithm.
// HMAC uses the raw secret bytes; asymmetric families require a PEM-encoded private key in JWT_SECRET_KEY.
func GetSigningKey() (any, error) {
	m := Config.SigningMethod
	key := []byte(Config.JWTSecretKey)

	switch {
	case strings.HasPrefix(m, "HS"):
		return key, nil
	case strings.HasPrefix(m, "RS") || strings.HasPrefix(m, "PS"):
		return jwt.ParseRSAPrivateKeyFromPEM(key)
	case strings.HasPrefix(m, "ES"):
		return jwt.ParseECPrivateKeyFromPEM(key)
	case m == "EdDSA":
		return jwt.ParseEdPrivateKeyFromPEM(key)
	default:
		return key, nil
	}
}

// GetVerificationKey returns the correct key type for verifying a token.
// HMAC reuses the secret; asymmetric families use the PEM-encoded public key in JWT_PUBLIC_KEY.
func GetVerificationKey() (any, error) {
	m := Config.SigningMethod
	privateKey := []byte(Config.JWTSecretKey)
	publicKey := []byte(Config.JWTPublicKey)

	switch {
	case strings.HasPrefix(m, "HS"):
		return privateKey, nil
	case strings.HasPrefix(m, "RS") || strings.HasPrefix(m, "PS"):
		return jwt.ParseRSAPublicKeyFromPEM(publicKey)
	case strings.HasPrefix(m, "ES"):
		return jwt.ParseECPublicKeyFromPEM(publicKey)
	case m == "EdDSA":
		return jwt.ParseEdPublicKeyFromPEM(publicKey)
	default:
		return privateKey, nil
	}
}
