package oauthserver

import (
	"time"

	"github.com/shieldoo/shieldoo-mesh-oauth/model"
)

type Maker interface {
	CreateToken(params *model.Params, duration time.Duration, userDetails *model.SysApiUserDetail) (string, time.Time, error)
	VerifyToken(token string) (*Payload, error)
}
