package main

import (
	"fmt"
	"os"
	"time"

	gofortify "github.com/iqbalatma/gofortify"
)

type User struct {
	ID   string
	Name string
}

func (u *User) GetSubjectKey() string {
	return u.ID
}

func main() {
	fmt.Println(time.Now())

	return
	// ── config ──────────────────────────────────────────────────────────────
	os.Setenv("JWT_SIGNING_METHOD", "HS256")
	// For HMAC: JWT_SECRET_KEY = shared secret, JWT_PUBLIC_KEY = (empty)
	// For asymmetric (RS*/PS*/ES*/EdDSA): JWT_SECRET_KEY = PEM private key, JWT_PUBLIC_KEY = PEM public key
	os.Setenv("JWT_SECRET_KEY", "super-secret-key-change-in-production")
	os.Setenv("JWT_PUBLIC_KEY", "")
	os.Setenv("JWT_ACCESS_TOKEN_TTL", "30")
	os.Setenv("JWT_REFRESH_TOKEN_TTL", "10080")
	os.Setenv("JWT_REDIS_HOST", "localhost")
	os.Setenv("JWT_REDIS_PORT", "6379")
	os.Setenv("JWT_REDIS_PASSWORD", "")
	os.Setenv("JWT_REDIS_DB", "1")
	os.Setenv("JWT_BLACKLIST_INCIDENT_TIME_KEY", "gofortify:incident")

	gofortify.LoadJWTConfig()

	fmt.Println(gofortify.Config)
	fmt.Println(gofortify.RDB)
	return
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
