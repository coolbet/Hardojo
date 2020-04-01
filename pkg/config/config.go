package config

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type Config struct {
	HarborConfig struct {
		Url          string `yaml:"url"`
		User         string `yaml:"user"`
		Password     string `yaml:"password_env_var"`
		ClientSecret string `yaml:"client_secret_env"`
		ClientId     string `yaml:"client_id"`
		OIDCLogin    bool   `yaml:"oidc_login"`
		OIDCEndpoint string `yaml:"oidc_endpoint"`
	} `yaml:"harbor"`
	DojoConfig struct {
		Url     string `yaml:"url"`
		UserId  int    `yaml:"user_id"`
		Token   string `yaml:"token_env_var"`
		Product int    `yaml:"docker_images_product_id"`
	} `yaml:"dojo"`
	Hook struct {
		AuthToken  string `yaml:"auth_token_env_var"`
		Host       string `yaml:"host"`
		Port       int    `yaml:"port"`
		Debug      bool   `yaml:"debug"`
		MaxWorkers int    `yaml:"max_workers"`
	}
}

func New(configFile string) Config {
	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.WithFields(log.Fields{
			"Error": err,
		}).Fatal("Could not read config file")
	}
	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.WithFields(log.Fields{
			"Error": err,
		}).Fatal("Could not parse config file.")
	}
	if config.Hook.Host == "" {
		config.Hook.Host = "127.0.0.1"
	}
	if config.Hook.Port == 0 {
		config.Hook.Port = 4444
	}
	config.Hook.AuthToken = os.Getenv(config.Hook.AuthToken)
	config.HarborConfig.ClientSecret = os.Getenv(config.HarborConfig.ClientSecret)
	config.HarborConfig.Password = os.Getenv(config.HarborConfig.Password)
	config.DojoConfig.Token = os.Getenv(config.DojoConfig.Token)
	if len(config.Hook.AuthToken) == 0 {
		log.Fatal("No Authentication Token provided via Environment Variable. Aborting.")
	}
	if len(config.DojoConfig.Token) == 0 {
		log.Fatal("No Dojo Token provided via Environment Variable. Aborting.")
	}
	if config.HarborConfig.OIDCLogin && len(config.HarborConfig.ClientSecret) == 0 {
		log.Fatal("OICD Login enabled but no client secret provided via Environment Variable. Aborting")
	}
	if len(config.HarborConfig.Password) == 0 {
		log.Warning("No Harbor Password provided via ENV Var, falling back of default insecure password.")
		config.HarborConfig.Password = "Harbor12345"
	}
	if config.Hook.MaxWorkers == 0 {
		log.Warning("No max_worker specified, running with default 1 worker")
		config.Hook.MaxWorkers = 1
	}
	return config
}
