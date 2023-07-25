package oauthserver

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/shieldoo/shieldoo-mesh-oauth/model"
)

type JWTHS256Maker struct {
	secretKey string
}

const minSecretKeySize = 32

func NewJWTHS256Maker(secretKey string) (Maker, error) {
	if len(secretKey) < minSecretKeySize {
		return nil, fmt.Errorf("invalid key size: must be at least %d characters", minSecretKeySize)
	}
	return &JWTHS256Maker{secretKey}, nil
}

func (maker *JWTHS256Maker) CreateToken(params *model.Params, duration time.Duration, details *model.SysApiUserDetail) (string, time.Time, error) {
	payload, err := NewPayload(params, duration, details)
	if err != nil {
		return "", time.Now().UTC(), err
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	rets, reterr := jwtToken.SignedString([]byte(maker.secretKey))
	return rets, payload.ExpiryAt.Time, reterr
}

func (maker *JWTHS256Maker) VerifyToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, ErrInvalidToken
		}
		return []byte(maker.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &Payload{}, keyFunc)
	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(verr.Inner, ErrExpiredToken) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	payload, ok := jwtToken.Claims.(*Payload)
	if !ok {
		return nil, ErrInvalidToken
	}

	return payload, nil
}
