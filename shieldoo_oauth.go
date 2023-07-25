package shieldoo_oauth

import (
	"encoding/json"

	"github.com/shieldoo/shieldoo-mesh-oauth/adminbackend"
	"github.com/shieldoo/shieldoo-mesh-oauth/app"
	"github.com/shieldoo/shieldoo-mesh-oauth/handler"
	"github.com/shieldoo/shieldoo-mesh-oauth/oauthclient"
	"github.com/shieldoo/shieldoo-mesh-oauth/oauthserver"
	"github.com/shieldoo/shieldoo-mesh-oauth/utils"

	log "github.com/sirupsen/logrus"
)

var cfg *utils.Config

// Init initializes the package
func Init() *utils.Config {
	log.SetLevel(log.InfoLevel)
	cfg = utils.ReadConfig()
	log.SetLevel(log.Level(cfg.Server.Loglevel))
	logdata, _ := json.Marshal(cfg)
	log.Debug("config-data: ", string(logdata))
	handler.Init(cfg)
	adminbackend.Init(cfg)
	oauthserver.Init(cfg)
	oauthclient.Init(cfg)
	return cfg
}

// Starts the package
func Run() {
	app.Run(cfg)
}
