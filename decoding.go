package gofortify

import (
	"github.com/golang-jwt/jwt/v5"
)

func Decode(jwtString string) (*Payload, error) {
	payload := &Payload{}
	token, err := jwt.Parse(jwtString, func(t *jwt.Token) (interface{}, error) {
		return GetVerificationKey()
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
