package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	gofortify "github.com/iqbalatma/gofortify"
)

type User struct {
	ID   string
	Name string
}

func (u *User) GetSubjectKey() string {
	return u.ID
}

func generateEdDSAKeys() (privatePEM string, publicPEM string) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)

	privBytes, _ := x509.MarshalPKCS8PrivateKey(privKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	pubBytes, _ := x509.MarshalPKIXPublicKey(pubKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	return string(privPEM), string(pubPEM)
}

func main() {
	// ── generate EdDSA key pair ──────────────────────────────────────────────
	privPEM, pubPEM := generateEdDSAKeys()
	fmt.Println("=== Generated EdDSA Keys ===")
	fmt.Println("Private Key:\n", privPEM)
	fmt.Println("Public Key:\n", pubPEM)

	// ── config ──────────────────────────────────────────────────────────────
	os.Setenv("JWT_SIGNING_METHOD", "EdDSA")
	os.Setenv("JWT_SECRET_KEY", privPEM)
	os.Setenv("JWT_PUBLIC_KEY", pubPEM)
	os.Setenv("JWT_ACCESS_TOKEN_TTL", "30")
	os.Setenv("JWT_REFRESH_TOKEN_TTL", "10080")
	os.Setenv("JWT_REDIS_HOST", "localhost")
	os.Setenv("JWT_REDIS_PORT", "6379")
	os.Setenv("JWT_REDIS_PASSWORD", "")
	os.Setenv("JWT_REDIS_DB", "1")
	os.Setenv("JWT_BLACKLIST_INCIDENT_TIME_KEY", "gofortify:incident")
	os.Setenv("JWT_BLACKLIST_DRIVER", "memory")

	gofortify.LoadJWTConfig()
	user := &User{ID: "1", Name: "Alice"}

	// ── Encode access token ──────────────────────────────────────────────────
	fmt.Println("=== Encode Access Token ===")
	accessToken, atv, err := gofortify.Encode(user, gofortify.AccessToken, true, "my-service", "Mozilla/5.0")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Access Token :", accessToken)
	fmt.Println("ATV          :", atv)

	// ── Encode refresh token ─────────────────────────────────────────────────
	fmt.Println("\n=== Encode Refresh Token ===")
	refreshToken, _, err := gofortify.Encode(user, gofortify.RefreshToken, false, "my-service", "Mozilla/5.0")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Refresh Token:", refreshToken)

	// ── Validate access token ────────────────────────────────────────────────
	fmt.Println("\n=== Validate Access Token ===")
	payload, err := gofortify.ValidateAccessToken(&accessToken, &atv)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("SUB  : %s\n", payload.SUB)
		fmt.Printf("ISS  : %s\n", payload.ISS)
		fmt.Printf("TYPE : %s\n", payload.TYPE)
		fmt.Printf("JTI  : %s\n", payload.JTI)
		fmt.Printf("IUC  : %v\n", payload.IUC)
		fmt.Printf("EXP  : %d\n", payload.EXP)
	}

	// ── Validate refresh token ───────────────────────────────────────────────
	fmt.Println("\n=== Validate Refresh Token ===")
	rPayload, err := gofortify.ValidateRefreshToken(&refreshToken)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("SUB  : %s\n", rPayload.SUB)
		fmt.Printf("TYPE : %s\n", rPayload.TYPE)
	}

	// ── Revoke access token ──────────────────────────────────────────────────
	fmt.Println("\n=== Revoke Access Token ===")
	revokeToken := accessToken // copy before it gets mutated
	_, err = gofortify.Revoke(&revokeToken)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Token revoked successfully")
	}

	// ── Validate after revoke (should fail) ──────────────────────────────────
	fmt.Println("\n=== Validate After Revoke (should fail) ===")
	_, err = gofortify.ValidateAccessToken(&accessToken, &atv)
	if err != nil {
		fmt.Println("Expected error:", err)
	} else {
		fmt.Println("ERROR: token should have been rejected")
	}
}
