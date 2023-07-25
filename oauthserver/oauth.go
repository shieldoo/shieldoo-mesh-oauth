package oauthserver

import (
	"errors"
	"os"
	"time"

	"github.com/shieldoo/shieldoo-mesh-oauth/model"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"
	log "github.com/sirupsen/logrus"
)

var globJwtMaker Maker
var _cfg *utils.Config

const (
	HS256 = "HS256"
	RS256 = "RS256"
)

func Init(cfg *utils.Config) {
	_cfg = cfg

	var err error
	switch cfg.OAuthServer.Signing.Method {
	case HS256:
		globJwtMaker, err = NewJWTHS256Maker(cfg.OAuthServer.Signing.Hs256.Secret)
	case RS256:
		globJwtMaker, err = NewJWTRS256Maker(cfg.OAuthServer.Signing.Rs256.PrivateKeyPath, cfg.OAuthServer.Signing.Rs256.PublicKeyPath, cfg.OAuthServer.Signing.Rs256.JwkId)
		printUsedKeys()
	default:
		err = errors.New("Unknown method " + cfg.OAuthServer.Signing.Method)
	}

	if err != nil {
		log.Panic("Unable initialize OauthServer: ", err)
		os.Exit(1000)
	}
}

func CreateToken(params *model.Params, userDetails *model.SysApiUserDetail) (string, time.Time, error) {
	return globJwtMaker.CreateToken(params,
		time.Second*time.Duration(_cfg.OAuthServer.Duration), userDetails)
}

func CreateInternalToken(params *model.Params) string {
	token, _, err := globJwtMaker.CreateToken(params,
		time.Second*time.Duration(_cfg.OAuthServer.InternalDuration), &model.SysApiUserDetail{Roles: []string{RoleSystem}})
	if err != nil {
		log.Error("Unable to create internal token: ", err)
		return ""
	}
	return token
}

func VerifyToken(token string) (*Payload, error) {
	return globJwtMaker.VerifyToken(token)
}
