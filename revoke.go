package gofortify

import (
	"time"

	"github.com/iqbalatma/gofortify/blacklist"
)

func Revoke(jwtToken *string) (*Payload, error) {
	RemoveBearer(jwtToken)
	payload, err := Decode(*jwtToken)
	if err != nil {
		return nil, err
	}
	ttl := time.Unix(payload.EXP, 0).Sub(time.Now())
	blacklist.AddBlacklistToken(payload.JTI, ttl)

	return payload, nil
}
