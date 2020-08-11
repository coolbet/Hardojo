package main

import (
	"Hardojo/pkg/config"
	"Hardojo/pkg/dojo"
	"Hardojo/pkg/harbor"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type PostHandler struct {
	config    *config.Config
	harbor    *harbor.HarborInstance
	dojo      *dojo.DojoInstance
	workloads chan VulnerabilityWorkload
}

type webhookRequest struct {
	WebhookType string `json:"type"`
	Timestamp   int    `json:"occur_at"`
	Operator    string `json:"operator"`
	Data        struct {
		Resources []struct {
			Digest       string                 `json:"digest"`
			Tag          string                 `json:"tag"`
			ResourceUrl  string                 `json:"resource_url"`
			ScanOverview map[string]interface{} `json:"scan_overview"`
		} `json:"resources"`
		Repository struct {
			Created   int    `json:"date_created"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			FullName  string `json:"repo_full_name"`
			RepoType  string `json:"repo_type"`
		} `json:"repository"`
	} `json:"event_data"`
}

type VulnerabilityWorkload struct {
	TestID     int
	Vuln       harbor.Vulnerability
	EndpointID int
}

func worker(id int, postHandler PostHandler) {
	for workload := range postHandler.workloads {
		_, findingError := postHandler.dojo.SubmitFindings(workload.TestID, workload.Vuln, workload.EndpointID)
		if findingError != nil {
			log.WithFields(log.Fields{
				"Worker_ID": id,
			}).Error(findingError)
		} else {
			log.WithFields(log.Fields{
				"Worker_ID": id,
			}).Debug("Submitted finding to Dojo")
		}
	}
}

func GetTokenFromHeader(AuthHeader []string) string {
	defer func() {
		if err := recover(); err != nil {
			log.Warning("No Authorization header detected")
		}
	}()
	Token := AuthHeader[0]
	return Token
}

func (c PostHandler) WebhookHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		io.WriteString(w, "OK\n")
		return
	}
	if req.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	Token := GetTokenFromHeader(req.Header["Authorization"])
	if Token != c.config.Hook.AuthToken {
		log.Error("Invalid Token received")
		http.Error(w, "Invalid Token", http.StatusUnauthorized)
		return
	}
	var webhookData webhookRequest
	err := json.NewDecoder(req.Body).Decode(&webhookData)
	if err != nil {
		http.Error(w, "Invalid JSON data", http.StatusInternalServerError)
		return
	}
	log.WithFields(log.Fields{
		"Webhook Type": webhookData.WebhookType,
	}).Info("Webhook Received")
	if webhookData.WebhookType != "scanningCompleted" {
		io.WriteString(w, "OK\n")
		return
	}
	// Do the actual processing
	ImageName := webhookData.Data.Repository.FullName
	ImageTag := webhookData.Data.Resources[0].Tag
	ResourceUrl := webhookData.Data.Resources[0].ResourceUrl
	vulnDataRaw, VulnErr := c.harbor.GetVulnerabilityDetails(ImageName, ImageTag)
	if VulnErr != nil {
		log.Error(VulnErr)
		return
	}
	vulnData := vulnDataRaw["application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"]
	io.WriteString(w, "Success\n")
	log.WithFields(log.Fields{
		"Vulnerabilities": len(vulnData.Vulnerabilities),
		"Image_Name":      ImageName,
		"Image_Tag":       ImageTag,
	}).Info("Received vulnerability data.")
	EndpointID, endpointErr := c.dojo.GetEndpointID(ResourceUrl)
	if endpointErr != nil {
		log.Error(endpointErr)
		return
	}
	if EndpointID == 0 {
		EndpointID, endpointErr = c.dojo.CreateEndpoint(ResourceUrl)
	}
	if endpointErr != nil {
		log.Error(endpointErr)
		return
	}
	EngagementID, engagementErr := c.dojo.CreateEngagement(fmt.Sprintf("%v:%v", ImageName, ImageTag))
	if engagementErr != nil {
		log.Error(engagementErr)
		return
	}
	TestID, testError := c.dojo.CreateTest(EngagementID)
	if testError != nil {
		log.Error(testError)
		return
	}

	for _, vuln := range vulnData.Vulnerabilities {
		workload := VulnerabilityWorkload{TestID, vuln, EndpointID}
		c.workloads <- workload
	}
	engagementErr = c.dojo.CloseEngagement(EngagementID)
	if engagementErr != nil {
		log.Error(engagementErr)
	}
}

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
}

func main() {
	configFile := flag.String("config", "config.yaml", "The configuration file for hardojo.")
	flag.Parse()
	config := config.New(*configFile)
	if config.Hook.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	harbor := harbor.NewHarborInstance(config)
	dojo := dojo.NewDojoInstance(config)
	workloads := make(chan VulnerabilityWorkload, config.Hook.MaxWorkers)
	handler := PostHandler{&config, &harbor, &dojo, workloads}
	for i := 0; i < cap(workloads); i++ {
		go worker(i, handler)
	}
	Host := config.Hook.Host
	Port := config.Hook.Port
	http.HandleFunc("/", handler.WebhookHandler)
	ListenString := fmt.Sprintf("%s:%d", Host, Port)
	log.WithFields(log.Fields{
		"Address": ListenString,
	}).Info("Listening for incoming Webhooks")
	log.Fatal(http.ListenAndServe(ListenString, nil))
}
