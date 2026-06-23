package gofortify

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func getDefaultPayload() *Payload {
	return &Payload{
		ATV:  "",
		ISS:  Config.IssuerServer,
		IAT:  time.Now().Unix(),
		EXP:  time.Now().Unix(),
		NBF:  time.Now().Unix(),
		JTI:  "",
		PTI:  "",
		SUB:  "",
		IUA:  "",
		IUC:  true,
		TYPE: AccessToken,
	}
}

func Encode(
	subject Subject,
	tokenType TokenType,
	iuc bool,
	iua string,
	jti string,
	pti string,
) (string, string, error) {
	key, err := GetSigningKey()
	if err != nil {
		return "", "", err
	}

	payload := getDefaultPayload()
	incidentTime, incidentErr := GetIncidentTime()
	if incidentErr != nil { //it's mean incident time is not set or wrong form, then it will set at this time
		payload.EXP = incidentTime
		payload.NBF = incidentTime
		payload.IAT = incidentTime
	}
	payload.TYPE = tokenType
	payload.SUB = subject.GetSubjectKey()
	payload.IUA = iua
	payload.IUC = iuc
	payload.JTI = jti
	payload.PTI = pti

	atv, err := addATV(payload)
	if err != nil {
		return "", "", err
	}

	addTTL(payload)

	token := jwt.NewWithClaims(GetSigningMethod(),
		payload.ToMapClaims(),
	)

	signedString, err := token.SignedString(key)
	if err != nil {
		return "", "", err
	}
	return signedString, atv, err
}

func addTTL(payload *Payload) {
	if payload.TYPE == AccessToken {
		payload.EXP = time.Now().Add(time.Duration(Config.AccessTokenTTL) * time.Minute).Unix()
	} else {
		payload.EXP = time.Now().Add(time.Duration(Config.RefreshTokenTTL) * time.Minute).Unix()
	}
}

func addATV(payload *Payload) (string, error) {
	if payload.TYPE == AccessToken {
		var atv = uuid.New().String()
		bytes, err := bcrypt.GenerateFromPassword([]byte(atv), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
		payload.ATV = string(bytes)

		return atv, nil
	}

	return "", nil
}
