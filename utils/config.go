package utils

import (
	"os"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type StaticAudience struct {
	Name         string `yaml:"name" envconfig:"NAME"`
	Redirect     string `yaml:"redirect" envconfig:"REDIRECT"`
	Authorize    bool   `yaml:"authorize" envconfig:"AUTHORIZE"`
	AuthorizeUrl string `yaml:"authorizeUrl" envconfig:"AUTHORIZEURL"`
}

type Signing struct {
	Method string `yaml:"method" envconfig:"METHOD"`
	Rs256  Rs256  `yaml:"rs256" envconfig:"RS256"`
	Hs256  Hs256  `yaml:"hs256" envconfig:"HS256"`
}

type Rs256 struct {
	PrivateKeyPath string `yaml:"private_key_path" envconfig:"OAUTHSERVER_SIGNING_RS256_PRIVATEKEY"`
	PublicKeyPath  string `yaml:"public_key_path" envconfig:"OAUTHSERVER_SIGNING_RS256_PUBLICKEY"`
	JwkId          string `yaml:"jwk_id" envconfig:"OAUTHSERVER_SIGNING_RS256_JWKID"`
}

type Hs256 struct {
	Secret string `yaml:"secret" envconfig:"OAUTHSERVER_SIGNING_HS256_SECRET"`
}

type Config struct {
	Server struct {
		Port     string `yaml:"port" envconfig:"PORT"`
		Uri      string `yaml:"uri" envconfig:"URI"`
		Loglevel int    `yaml:"loglevel" envconfig:"LOGLEVEL"`
	} `yaml:"server"`
	AdminBackend struct {
		BaseUrl string `yaml:"base_url" envconfig:"BASEURL"`
	} `yaml:"adminbackend"`
	OAuthServer struct {
		Duration         int              `yaml:"duration" envconfig:"DURATION"`
		InternalDuration int              `yaml:"internal_duration" envconfig:"INTERNALDURATION"`
		DefaultAudience  string           `yaml:"default_audience" envconfig:"DEFAULTAUDIENCE"`
		StaticAudiences  []StaticAudience `yaml:"static_audience" envconfig:"STATICAUDIENCE"`
		Signing          Signing          `yaml:"signing" envconfig:"SIGNING"`
		Issuer           string           `yaml:"issuer" envconfig:"ISSUER"`
		RedirectDomain   string           `yaml:"redirect_domain" envconfig:"REDIRECTDOMAIN"`
	} `yaml:"oauthserver"`
	Aad struct {
		ClientId     string   `yaml:"clientid" envconfig:"CLIENTID"`
		ClientSecret string   `yaml:"clientsecret" envconfig:"CLIENTSECRET"`
		TenantId     string   `yaml:"tenantid" envconfig:"TENANTID"`
		CallbackUrl  string   `yaml:"callback_url" envconfig:"CALLBACKURL"`
		JwksUri      string   `yaml:"jwksuri" envconfig:"JWKSURI"`
		Issuers      []string `yaml:"issuers"`
	} `yaml:"aad"`
	Google struct {
		ClientId     string   `yaml:"clientid" envconfig:"CLIENTID"`
		ClientSecret string   `yaml:"clientsecret" envconfig:"CLIENTSECRET"`
		CallbackUrl  string   `yaml:"callback_url" envconfig:"CALLBACKURL"`
		Issuers      []string `yaml:"issuers"`
	} `yaml:"google"`
	BasicAuth struct {
		Enabled bool   `yaml:"enabled" envconfig:"ENABLED"`
		Users   string `yaml:"users" envconfig:"USERS"`
	} `yaml:"basicauth"`
}

var cfg Config

func ReadConfig() *Config {
	readFile(&cfg)
	readEnv(&cfg)
	log.Debug("App config:")
	log.Debug(cfg)
	return &cfg
}

func processError(err error) {
	log.Panic(err)
	os.Exit(2)
}

func readFile(cfg *Config) {
	f, err := os.Open("config.yaml")
	if err != nil {
		processError(err)
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(cfg)
	if err != nil {
		processError(err)
	}
}

func readEnv(cfg *Config) {
	err := envconfig.Process("", cfg)
	if err != nil {
		processError(err)
	}
}

func FindStaticAudience(config Config, audience string) *StaticAudience {
	for _, v := range config.OAuthServer.StaticAudiences {
		if v.Name == audience {
			return &v
		}
	}
	return nil
}
