package gofortify

import (
	"time"

	"golang.org/x/crypto/bcrypt"
)

func ValidateAccessToken(jwtToken *string, accessTokenVerifier *string) (*Payload, error) {
	RemoveBearer(jwtToken)
	payload, err := Decode(*jwtToken)

	if err != nil {
		return nil, err
	}
	ttlBasedOnExpiredAt := time.Until(time.Unix(payload.EXP, 0))

	incidentTime, err := GetIncidentTime()

	//if not nil, it's mean incident time is not set, could be redis is broken or shutdown, blacklist all jwt before this incident
	if err != nil {
		GetBlacklist().Set(payload.JTI, true, ttlBasedOnExpiredAt)
		GetBlacklist().Set(payload.PTI, true, ttlBasedOnExpiredAt)
		return nil, ErrExpiredToken
	}

	//it's mean this token is created before incident time, could be it's actually on blacklist but the list is gone
	//so blacklist all token that created before incident time
	if payload.IAT < incidentTime {
		GetBlacklist().Set(payload.JTI, true, ttlBasedOnExpiredAt)
		GetBlacklist().Set(payload.PTI, true, ttlBasedOnExpiredAt)
		return nil, ErrExpiredToken
	}

	// check token type, make sure this is access token
	if payload.TYPE != AccessToken {
		return nil, ErrInvalidTokenType
	}

	//if now greater than exp, mean it's already expired, no need to check blacklist
	if time.Now().Unix() > payload.EXP {
		return nil, ErrExpiredToken
	}

	//check is on blacklist
	jti := GetBlacklist().Get(payload.JTI)

	//when jti is on blacklist
	if jti != nil {
		return nil, ErrExpiredToken
	}

	//check is atv is valid
	if payload.IUC {
		if accessTokenVerifier == nil {
			return nil, ErrMissingRequiredAccessTokenVerifierCookie
		}

		//improve this by using cached hashing check
		err := bcrypt.CompareHashAndPassword([]byte(payload.ATV), []byte(*accessTokenVerifier))
		if err != nil {
			return nil, ErrInvalidAccessTokenVerifier
		}
	}

	return payload, nil
}
