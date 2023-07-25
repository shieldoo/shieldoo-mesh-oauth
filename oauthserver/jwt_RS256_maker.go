package oauthserver

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	log "github.com/sirupsen/logrus"
)

type JWTRS256Maker struct {
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
	jwkId     string
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func initKeys(privateKeyPath string, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	signBytes, err := ioutil.ReadFile(privateKeyPath)
	fatal(err)

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := ioutil.ReadFile(publicKeyPath)
	fatal(err)

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)
	if err != nil {
		return nil, nil, err
	} else {
		return signKey, verifyKey, nil
	}
}

func NewJWTRS256Maker(privateKeyPath string, publicKeyPath string, jwkId string) (Maker, error) {
	signKey, verifyKey, err := initKeys(privateKeyPath, publicKeyPath)
	if err != nil {
		return nil, err
	}
	return &JWTRS256Maker{signKey: signKey, verifyKey: verifyKey, jwkId: jwkId}, nil
}

func (maker *JWTRS256Maker) CreateToken(params *model.Params, duration time.Duration, details *model.SysApiUserDetail) (string, time.Time, error) {
	payload, err := NewPayload(params, duration, details)
	if err != nil {
		return "", time.Now().UTC(), err
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	jwtToken.Header["kid"] = maker.jwkId
	rets, reterr := jwtToken.SignedString(maker.signKey)
	return rets, payload.ExpiryAt.Time, reterr
}

func (maker *JWTRS256Maker) VerifyToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, ErrInvalidToken
		}
		return maker.verifyKey, nil
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
