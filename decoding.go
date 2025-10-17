package gofortify

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/iqbalatma/gofortify/config"
)

func Decode(jwtString string) (*Payload, error) {
	key := []byte(config.Config.JWTSecretKey)
	payload := &Payload{}
	token, err := jwt.Parse(jwtString, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if err != nil {
		return nil, err
	}

	//from parse to jwt claims
	claims, _ := token.Claims.(jwt.MapClaims)
	err = payload.FromMapClaims(claims)

	if err != nil {
		return nil, err
	}
	return payload, nil
}
