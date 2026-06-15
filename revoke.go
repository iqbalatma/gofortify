package gofortify

import (
	"time"
)

func Revoke(jwtToken *string) (*Payload, error) {
	RemoveBearer(jwtToken)
	payload, err := Decode(*jwtToken)
	if err != nil {
		return nil, err
	}
	ttl := time.Unix(payload.EXP, 0).Sub(time.Now())
	AddBlacklistToken(payload.JTI, ttl)

	return payload, nil
}
