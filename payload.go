package gofortify

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const (
	AccessToken  TokenType = "access_token"
	RefreshToken TokenType = "refresh_token"
)

type Payload struct {
	ISS  string    `json:"iss"`  //issuer: server that signed and issue this token
	IAT  int64     `json:"iat"`  //issue at: time when this token is signed
	EXP  int64     `json:"exp"`  //expired at: time when this token is expired
	NBF  int64     `json:"nbf"`  //not valid before: time when this token start to valid
	JTI  string    `json:"jti"`  //json token identifier: unique identifier to this token
	PTI  string    `json:"pti"`  //pair token identifier: unique identifier to pair token
	SUB  string    `json:"sub"`  //subject: user that own this token
	IUA  string    `json:"iua"`  //issued user agent: user agent that issued this token
	IUC  bool      `json:"iuc"`  //is using cookie: condition when this token used for mobile
	TYPE TokenType `json:"type"` //type : this token type, could be access and refresh
	ATV  string    `json:"atv"`  //access token verifier: access token verifier that used to bind access token
}

func (p *Payload) ToMapClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"atv":  p.ATV,
		"iss":  p.ISS,
		"iat":  p.IAT,
		"exp":  p.EXP,
		"nbf":  p.NBF,
		"jti":  p.JTI,
		"pti":  p.PTI,
		"sub":  p.SUB,
		"iua":  p.IUA,
		"iuc":  p.IUC,
		"type": p.TYPE,
	}
}

func (p *Payload) FromMapClaims(mc jwt.MapClaims) error {
	b, err := json.Marshal(mc)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, p)
}
