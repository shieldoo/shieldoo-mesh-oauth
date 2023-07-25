package oauthserver

import (
	"encoding/json"
	"errors"

	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
)

type JwksList struct {
	Keys []jwk.Key `json:"keys"`
}

type OpenIdConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	JwksUri               string `json:"jwks_uri"`
}

func GenerateJwks() *JwksList {
	jwkInfo, err := generateJwkInfo()
	if err != nil {
		return nil
	}
	return &JwksList{Keys: []jwk.Key{jwkInfo}}
}

func GenerateOpenIdConfiguration() *OpenIdConfiguration {
	return &OpenIdConfiguration{Issuer: _cfg.OAuthServer.Issuer, JwksUri: _cfg.OAuthServer.Issuer + "/oauth2/v1/certs"}
}

func printUsedKeys() {
	bytes, err := json.MarshalIndent(
		GenerateJwks(),
		"",
		" ",
	)
	if err != nil {
		return
	}
	log.Info("Keys used for generating JWT signature: \n", string(bytes))
}

func generateJwkInfo() (jwk.Key, error) {

	jWtRs256Maker, ok := globJwtMaker.(*JWTRS256Maker)
	if !ok {
		return nil, errors.New("rs256 is not enabled")
	}
	publicKeyJwk, err := jwk.New(jWtRs256Maker.verifyKey)
	if err != nil {
		log.Error("failed to create RSA key: %s\n", err)
		return nil, err
	}
	if _, ok := publicKeyJwk.(jwk.RSAPublicKey); !ok {
		log.Error("expected jwk.RSAPublicKey, got %T\n", publicKeyJwk)
		return nil, err
	}
	err = publicKeyJwk.Set(jwk.KeyIDKey, jWtRs256Maker.jwkId)
	if err != nil {
		return nil, err
	}
	err = publicKeyJwk.Set(jwk.KeyUsageKey, jwk.ForSignature)
	if err != nil {
		return nil, err
	}
	err = publicKeyJwk.Set(jwk.AlgorithmKey, "RS256")
	if err != nil {
		return nil, err
	}

	return publicKeyJwk, nil

}
