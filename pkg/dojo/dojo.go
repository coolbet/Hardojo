package dojo

import (
	"Hardojo/pkg/config"
	"Hardojo/pkg/harbor"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type DojoInstance struct {
	Url       string
	Username  int
	ApiKey    string
	ProductID int
}

type Endpoint struct {
	Id         int           `json:"id"`
	Tags       []interface{} `json:"tags"`
	Protocol   string        `json:"protocol"`
	Host       string        `json:"host"`
	Fqdn       string        `json:"fqdn"`
	Port       int           `json:"port"`
	Path       string        `json:"path"`
	Query      string        `json:"query"`
	Fragment   string        `json:"fragment"`
	Remediated bool          `json:"remediated"`
	Product    int           `json:"product"`
	Params     []interface{} `json:"params"`
}

type CreateEndpointResponse struct {
	Id         int           `json:"id"`
	Params     []interface{} `json:"endpoint_params"`
	Tags       []interface{} `json:"tags"`
	Protocol   string        `json:"protocol"`
	Host       string        `json:"host"`
	Fqdn       string        `json:"fqdn"`
	Port       int           `json:"port"`
	Path       string        `json:"path"`
	Query      string        `json:"query"`
	Fragment   string        `json:"fragment"`
	Remediated bool          `json:"remediated"`
	Product    int           `json:"product"`
}

type EndpointResponse struct {
	Count     int        `json:"count"`
	Next      string     `json:"next"`
	Previous  string     `json:"previous"`
	Endpoints []Endpoint `json:"results"`
}

func NewDojoInstance(config config.Config) DojoInstance {
	Instance := DojoInstance{config.DojoConfig.Url,
		config.DojoConfig.UserId,
		config.DojoConfig.Token,
		config.DojoConfig.Product}
	return Instance
}

func (d DojoInstance) GetEndpointID(resourceUrl string) (int, error) {
	var endpointList []Endpoint
	PageLimit := 100
	ApiUrl := fmt.Sprintf("%v/api/v2/endpoints/?limit=%v", d.Url, PageLimit)
	httpClient := http.Client{}
	req, err := http.NewRequest(http.MethodGet, ApiUrl, nil)
	if err != nil {
		log.Error(err)
		return 0, errors.New("Failure to prepare a request to Dojo endpoint URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %v", d.ApiKey))
	res, getErr := httpClient.Do(req)
	if getErr != nil {
		log.Error(getErr)
		return 0, errors.New("Request to Dojo endpoint URL failed")
	}
	defer res.Body.Close()
	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Error(readErr)
		return 0, errors.New("Failure to read response from Dojo Endpoint URL")
	}
	endpointResponse := EndpointResponse{}
	jsonErr := json.Unmarshal(body, &endpointResponse)
	if jsonErr != nil {
		log.Error(jsonErr)
		return 0, errors.New("Response from Dojo Endpoint URL was not valid Json")
	}
	endpointList = append(endpointList, endpointResponse.Endpoints...)
	for endpointResponse.Next != "" {
		httpClient = http.Client{}
		req, err = http.NewRequest(http.MethodGet, endpointResponse.Next, nil)
		if err != nil {
			log.Error(err)
			return 0, errors.New("Failure to prepare a request to Dojo endpoint URL")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Token %v", d.ApiKey))
		res, getErr = httpClient.Do(req)
		if getErr != nil {
			log.Error(getErr)
			return 0, errors.New("Request to Dojo endpoint URL failed")
		}
		defer res.Body.Close()
		body, readErr = ioutil.ReadAll(res.Body)
		if readErr != nil {
			log.Error(readErr)
			return 0, errors.New("Failure to read response from Dojo Endpoint URL")
		}
		endpointResponse = EndpointResponse{}
		jsonErr = json.Unmarshal(body, &endpointResponse)
		if jsonErr != nil {
			log.Error(jsonErr)
			return 0, errors.New("Response from Dojo Endpoint URL was not valid Json")
		}
		endpointList = append(endpointList, endpointResponse.Endpoints...)

	}
	for _, value := range endpointList {
		if value.Host == resourceUrl {
			log.WithFields(log.Fields{
				"Host": value.Host,
				"ID":   value.Id,
			}).Info("Product found")
			return value.Id, nil
		}
	}
	return 0, nil
}

func (d DojoInstance) CreateEndpoint(resourceUrl string) (int, error) {
	ApiUrl := fmt.Sprintf("%v/api/v2/endpoints/", d.Url)
	httpClient := http.Client{}
	data := map[string]interface{}{
		"protocol":   "",
		"host":       resourceUrl,
		"fqdn":       "",
		"port":       0,
		"path":       "",
		"query":      "",
		"fragment":   "",
		"remediated": false,
		"product":    d.ProductID}
	jsonValue, _ := json.Marshal(data)
	req, err := http.NewRequest(http.MethodPost, ApiUrl, bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Error(err)
		return 0, errors.New("Failed to prepare request to Dojo Endpoint URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %v", d.ApiKey))
	res, postErr := httpClient.Do(req)
	if postErr != nil {
		log.Error(postErr)
		return 0, errors.New("Request to Dojo endpoint URL failed")
	}
	defer res.Body.Close()
	body, readErr := ioutil.ReadAll(res.Body)
	if res.StatusCode != 201 {
		log.WithFields(log.Fields{
			"Status Code": res.StatusCode,
			"Content":     body,
		}).Error("Failed to create endpoint")
		return 0, errors.New("Request to create a new Endpoint failed with a non-201 status code")
	}
	if readErr != nil {
		log.Error(readErr)
		return 0, errors.New("Failure to read response body from Endpoint URL")
	}
	createResponse := CreateEndpointResponse{}
	jsonErr := json.Unmarshal(body, &createResponse)
	if jsonErr != nil {
		log.WithFields(log.Fields{
			"Error": jsonErr,
		}).Error("Failed to create Endpoint.")
		return 0, errors.New("Response from Endpoint create URL was not valid Json")
	}
	log.WithFields(log.Fields{
		"ID": createResponse.Id,
	}).Info("Successfully create Endpoint")
	return createResponse.Id, nil
}

func (d DojoInstance) CreateEngagement(FullImageName string) (int, error) {
	ApiUrl := fmt.Sprintf("%v/api/v2/engagements/", d.Url)
	httpClient := http.Client{}
	currentTime := time.Now()
	today := currentTime.Format("2006-01-02")
	date := currentTime.Format("2006-01-02T15:04:05")
	data := map[string]interface{}{
		"product":                     d.ProductID,
		"name":                        fmt.Sprintf("Scan for %v", FullImageName),
		"lead":                        d.Username,
		"target_end":                  today,
		"target_start":                today,
		"description":                 fmt.Sprintf("Scan result for image %v that has just been scanned in Harbor.", FullImageName),
		"done_testing":                true,
		"deduplication_on_engagement": false,
		"active":                      false,
		"status":                      "Completed",
		"created":                     date}
	jsonValue, _ := json.Marshal(data)
	req, err := http.NewRequest(http.MethodPost, ApiUrl, bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Error(err)
		return 0, errors.New("Failed to prepare request to Dojo Engagement URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %v", d.ApiKey))
	res, postErr := httpClient.Do(req)
	if postErr != nil {
		log.Error(postErr)
		return 0, errors.New("Request to Dojo Engagement URL failed.")
	}
	defer res.Body.Close()
	body, readErr := ioutil.ReadAll(res.Body)
	if res.StatusCode != 201 {
		log.WithFields(log.Fields{
			"Status Code": res.StatusCode,
			"Content":     body,
		}).Error("Failed to create engagement")
		return 0, errors.New("Request to Engagement URL failed with a non-201 status code")
	}
	if readErr != nil {
		log.Error(readErr)
		return 0, errors.New("Failed to read the response body from Engagement URL")
	}
	responseData := make(map[string]interface{})
	jsonErr := json.Unmarshal(body, &responseData)
	if jsonErr != nil {
		log.WithFields(log.Fields{
			"Error": jsonErr,
		}).Error("Failed to create Engagement")
		return 0, errors.New("Response from Engagement endpoint was not valid Json")
	}
	EngagementID, ok := responseData["id"]
	if ok {
		ID, isInt := EngagementID.(float64)
		if isInt {
			log.WithFields(log.Fields{
				"ID": ID,
			}).Info("Successfully created Engagement")
			return int(ID), nil
		}
	}
	log.Error("Failed to create Engagement.")
	return 0, errors.New("The response did not contain a valid Engagement ID")
}

func (d DojoInstance) CreateTest(Engagement int) (int, error) {
	ApiUrl := fmt.Sprintf("%v/api/v2/tests/", d.Url)
	httpClient := http.Client{}
	currentTime := time.Now()
	date := currentTime.Format("2006-01-02T15:04:05")
	data := map[string]interface{}{
		"engagement":       Engagement,
		"title":            "Harbor Vulnerability Scan",
		"description":      "Vulnerability Scan result from Harbor",
		"target_start":     date,
		"target_end":       date,
		"percent_complete": 100,
		"test_type":        112,
		"environment":      1}
	jsonValue, _ := json.Marshal(data)
	req, err := http.NewRequest(http.MethodPost, ApiUrl, bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Error(err)
		return 0, errors.New("Failed to prepare request for Test endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %v", d.ApiKey))
	res, postErr := httpClient.Do(req)
	if postErr != nil {
		log.Error(postErr)
		return 0, errors.New("Request to Test endpoint failed")
	}
	defer res.Body.Close()
	body, readErr := ioutil.ReadAll(res.Body)
	if res.StatusCode != 201 {
		log.WithFields(log.Fields{
			"Status Code": res.StatusCode,
		}).Error("Failed to create test")
		return 0, errors.New("Request to Test endpoint failed with a non-201 status code")
	}
	if readErr != nil {
		log.Error(readErr)
		return 0, errors.New("Failed to read response from Test endpoint")
	}
	responseData := make(map[string]interface{})
	jsonErr := json.Unmarshal(body, &responseData)
	if jsonErr != nil {
		log.WithFields(log.Fields{
			"Error": jsonErr,
		}).Error("Failed to create Test")
		return 0, errors.New("Response from Test endpoint did not contain valid Json")
	}
	TestID, ok := responseData["id"]
	if ok {
		ID, isInt := TestID.(float64)
		if isInt {
			return int(ID), nil
		}
	}
	log.Error("Failed to create test.")
	return 0, errors.New("Test endpoint response did not contain a valid ID")
}

func (d DojoInstance) SubmitFindings(Test int, Finding harbor.Vulnerability, Endpoint int) (int, error) {
	ApiUrl := fmt.Sprintf("%v/api/v2/findings/", d.Url)
	httpClient := http.Client{}
	currentTime := time.Now()
	today := currentTime.Format("2006-01-02")
	if Finding.Severity == "Negligible" || Finding.Severity == "Unknown" {
		Finding.Severity = "Info"
	}
	data := map[string]interface{}{
		"test":               Test,
		"found_by":           []int{112},
		"title":              fmt.Sprintf("%v (%v, %v)", Finding.Id, Finding.Package, Finding.Version),
		"date":               today,
		"cwe":                0,
		"cve":                Finding.Id,
		"severity":           Finding.Severity,
		"description":        fmt.Sprintf("%v-%v", Finding.Id, Finding.Description),
		"mitigation":         fmt.Sprintf("Upgrade to: %v", Finding.FixVersion),
		"impact":             fmt.Sprintf("%v %v", Finding.Package, Finding.Version),
		"references":         strings.Join(Finding.Links, ","),
		"active":             true,
		"verified":           true,
		"duplicate":          false,
		"false_p":            false,
		"static_finding":     true,
		"numerical_severity": 4,
		"endpoints":          []int{Endpoint}}
	jsonValue, _ := json.Marshal(data)
	req, err := http.NewRequest(http.MethodPost, ApiUrl, bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Error(err)
		return 0, errors.New("Failed to prepare request for Finding endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %v", d.ApiKey))
	res, postErr := httpClient.Do(req)
	if postErr != nil {
		log.Error(postErr)
		return 0, errors.New("Request to Finding endpoint failed")
	}
	defer res.Body.Close()
	body, readErr := ioutil.ReadAll(res.Body)
	if res.StatusCode != 201 {
		log.WithFields(log.Fields{
			"Status Code": res.StatusCode,
		}).Error("Failed to create finding")
		return 0, errors.New("Request to Finding endpoint failed with a non-201 status code")
	}
	if readErr != nil {
		log.Error(readErr)
		return 0, errors.New("Failed to read the response from Finding endpoint")
	}
	responseData := make(map[string]interface{})
	jsonErr := json.Unmarshal(body, &responseData)
	if jsonErr != nil {
		log.WithFields(log.Fields{
			"Error": jsonErr,
		}).Error("Failed to create Finding")
		return 0, errors.New("Response from Finding endpoint did not contain valid Json")
	}
	FindingID, ok := responseData["id"]
	if ok {
		ID, isInt := FindingID.(float64)
		if isInt {
			log.WithFields(log.Fields{
				"ID": ID,
			}).Debug("Successfully Created Finding")
			return int(ID), nil
		}
	}
	log.Error("Failed to create Finding.")
	return 0, errors.New("Response from Finding endpoint did not contain a valid ID")
}

func (d DojoInstance) CloseEngagement(engagementID int) error {
	ApiUrl := fmt.Sprintf("%v/api/v2/engagements/%v/close/", d.Url, engagementID)
	httpClient := http.Client{}
	req, err := http.NewRequest(http.MethodGet, ApiUrl, nil)
	if err != nil {
		log.Error(err)
		return errors.New("Failure to prepare a request to Dojo endpoint URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Token %v", d.ApiKey))
	res, getErr := httpClient.Do(req)
	if getErr != nil {
		log.Error(getErr)
		return errors.New("Request to Dojo endpoint URL failed")
	}
	if res.StatusCode != 200 {
		return errors.New("Failure to close the engagement.")
	}
	return nil
}
