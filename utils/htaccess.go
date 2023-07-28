package utils

import (
	"strings"

	log "github.com/sirupsen/logrus"
	htp "github.com/tg123/go-htpasswd"
)

func CheckHtaccessUser(username string, password string) bool {
	htaccess := strings.ReplaceAll(cfg.BasicAuth.Users, "|", "\n")
	log.Debug("Endpoint Hit: utils.CheckHtaccessUser")
	log.Debug("Username: ", username)
	log.Debug("htaccess: ", htaccess)
	r := strings.NewReader(htaccess)

	h, err := htp.NewFromReader(r, htp.DefaultSystems, nil)
	if err != nil {
		log.Debug("Error reading htaccess: ", err)
	}

	return h.Match(username, password)
}
