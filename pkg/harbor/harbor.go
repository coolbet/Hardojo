package harbor

import (
	"Hardojo/pkg/config"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"

	"net/url"
)

type HarborInstance struct {
	Url          string
	OIDCLogin    bool
	Username     string
	Password     string
	ClientId     string
	ClientSecret string
	OIDCEndpoint string
}

type Vulnerability struct {
	Id          string   `json:"id"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	FixVersion  string   `json:"fix_version"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Links       []string `json:"links"`
}

type VulnerabilityReport map[string]struct {
	Timestamp       string            `json:"generated_at"`
	Scanner         map[string]string `json:"scanner"`
	Severity        string            `json:"severity"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
}

func NewHarborInstance(config config.Config) HarborInstance {
	Instance := HarborInstance{config.HarborConfig.Url,
		config.HarborConfig.OIDCLogin,
		config.HarborConfig.User,
		config.HarborConfig.Password,
		config.HarborConfig.ClientId,
		config.HarborConfig.ClientSecret,
		config.HarborConfig.OIDCEndpoint}
	return Instance
}

func (h HarborInstance) getOIDCToken() string {
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("client_id", h.ClientId)
	form.Add("client_secret", h.ClientSecret)
	form.Add("scope", "openid")
	form.Add("username", h.Username)
	form.Add("password", h.Password)
	log.Debug("Querying OIDC Endpoint for a token")
	resp, err := http.PostForm(h.OIDCEndpoint, form)
	if err != nil {
		log.Error(err)
		return ""
	}
	defer resp.Body.Close()
	responseData := make(map[string]interface{})
	decodeErr := json.NewDecoder(resp.Body).Decode(&responseData)
	if decodeErr != nil {
		log.Warning("No Token received from OIDC Endpoint")
		return ""
	}
	log.WithFields(log.Fields{
		"ResponseData": responseData,
	}).Debug("Received response from OIDC enpoint")
	idToken, ok := responseData["id_token"]
	if ok {
		token, isString := idToken.(string)
		if isString {
			log.WithFields(log.Fields{
				"StatusCode": resp.StatusCode,
				"Token":      idToken,
			}).Debug("Successfully retrieved OIDC Token")
			return token
		}
	}
	return ""
}

func (h HarborInstance) GetVulnerabilityDetails(image string, tag string) (VulnerabilityReport, error) {
	//First of all, let's see if we can use OIDC or simply BasicAuth
	client := http.Client{}
	imageEscaped := strings.Replace(image, "/", "%2F", 1)
	url := fmt.Sprintf("%s/api/repositories/%s/tags/%s/scan", h.Url, imageEscaped, tag)
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0")
	if h.OIDCLogin {
		OIDCToken := h.getOIDCToken()
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %v", OIDCToken))
	} else {
		req.SetBasicAuth(h.Username, h.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Unable to reach Harbor.")
	}
	defer resp.Body.Close()
	vulnData := VulnerabilityReport{}
	body, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		log.Error(readErr)
		return nil, errors.New("Error in reading response from Harbor.")
	} else {
		if resp.StatusCode != 200 {
			log.WithFields(log.Fields{
				"StatusCode": resp.StatusCode,
			}).Error("Request to Harbor failed.")
			return nil, errors.New("Request to harbor returned a non-200 status code")
		}
		jsonErr := json.Unmarshal(body, &vulnData)
		if jsonErr != nil {
			log.WithFields(log.Fields{
				"Error": jsonErr,
				"Body":  string(body),
			}).Error("Invalid JSON data.")
			return nil, errors.New("Data received from Harbor was not a valid Json")
		} else {
			_, ok := vulnData["application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"]
			if !ok {
				log.Error("Invalid vulnerability data received")
				return nil, errors.New("The data received from Harbor did not contain valid vulnerability data.")
			}
		}
	}
	return vulnData, nil
}
