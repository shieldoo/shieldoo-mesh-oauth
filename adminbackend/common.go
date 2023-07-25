package adminbackend

import (
	"os"

	"github.com/shieldoo/shieldoo-mesh-oauth/utils"
	log "github.com/sirupsen/logrus"
)

var _cfg *utils.Config

func Init(cfg *utils.Config) {
	_cfg = cfg
	var err error
	if err != nil {
		log.Panic("Unable initialize OauthClient: ", err)
		os.Exit(1000)
	}
}
