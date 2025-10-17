package gofortify

import (
	"time"

	"github.com/iqbalatma/gofortify/blacklist"
	"golang.org/x/crypto/bcrypt"
)

func ValidateAccessToken(jwtToken *string, accessTokenVerifier *string) (*Payload, error) {
	RemoveBearer(jwtToken)
	payload, err := Decode(*jwtToken)

	if err != nil {
		return nil, err
	}

	incidentTime, err := GetIncidentTime()

	//if not nil, it's mean incident time is not set, could be redis is broken, blacklist all jwt before this incident
	if err != nil {
		return nil, ErrExpiredToken
	}

	//it's mean this token is created before incident time, could be it's actually on blacklist but the list is gone
	//so blacklist all token that created before incident time
	if payload.IAT < incidentTime {
		return nil, ErrExpiredToken
	}

	// check token type, make sure this is access token
	if payload.TYPE != AccessToken {
		return nil, ErrInvalidTokenType
	}

	//check is on blacklist
	jti := blacklist.GetBlacklist().Get(payload.JTI)

	//when jti is on blacklist
	if jti != nil {
		return nil, ErrExpiredToken
	}

	//if now greater than exp, mean it's already expired
	if time.Now().Unix() > payload.EXP {
		return nil, ErrExpiredToken
	}

	//check is atv is valid
	if payload.IUC {
		if accessTokenVerifier == nil {
			return nil, ErrMissingRequiredAccessTokenVerifierCookie
		}

		err := bcrypt.CompareHashAndPassword([]byte(payload.ATV), []byte(*accessTokenVerifier))
		if err != nil {
			return nil, ErrInvalidAccessTokenVerifier
		}
	}

	return payload, nil
}
