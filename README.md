# Hardojo

The purpose of Hardojo is to "glue" together Harbor and DefectDojo, by importing in Dojo the
findings that Harbor's scanner (Clair or whatever is configured) produces.

The architecture is simple, there is a single GO binary that consumes the webhook(s) that Harbor sends, and reacts when a scan is completed (ignoring other events) by pushing all the individual findings to Defectdojo. A worker pool (defaulting to 1 worker) is used to avoid the saturation of Dojo.

## Features

* Supports Harbor OICD and local login
* Findings are parsed individually to be agnostic of scan type
* Docker image is ~6MB built from `scratch`

## Webhook Server

The webhook server listens for requests and once a scan is completed, it performs the
following actions:

* Queries back the vulnerability data to Harbor.
* Uses the IMAGE\_NAME:IMAGE\_TAG value to create a new *endpoint* in DefectDojo, if this doesn't
  exist already, in which case, it just fetches the ID of the corresponding endpoint.
* It creates a new *engagement* for the endpoint found.
* It creates a new *test* within the created engagement.
* Pushes all the findings to Dojo.

Note that this is an **opinionated** solution in several ways:

* It assumes that one product in Dojo is dedicated to Docker Images. (This product ID needs to be
  specified in the configuration file)
* It creates one endpoint per image in Dojo.
* It consumes all webhooks from Harbor, ignoring the non-relevant ones. This means that if some other
  webhook consumer is used, this should forward the relevant webhooks to Hardojo (or the same logic
  can be implemented in Hardojo).

## How to run it

The repository contains a *docker-compose* file that should make the deployment trivial.
Start by cloning this repository:

```bash
git clone https://github.com/coolbet/Hardojo
cd Hardojo
```

### Prepare the configuration

Edit the config.yaml.tmpl with the relevant values and rename it as `config.yaml`. The configuration is as follows:

```
harbor:
  # Harbor URL
  url: "https://harbor.example.com"
  # Harbor username
  user: "USERNAME"
  # ENV var in which the harbor password will be provided
  password_env_var: "HARBOR_PASSWORD"
  # If OIDC login is enabled in Harbor, this is the client ID in the OIDC provider (e.g., Keycloak)
  client_id: "OICDCLIENTNAME"
  # ENV var in which the OIDC client secret will be provided
  client_secret_env: "HARBOR_CLIENT_SECRET"
  # True if OIDC login is enabled in Harbor
  oidc_login: True
  # OIDC URL used to fetch a token for the user (e.g., for Keycloak)
  oidc_endpoint: "https://keycloak.example.com/auth/realms/realm/protocol/openid-connect/token"
dojo:
  # DefectDojo URL
  url: "https://dojo.example.com"
  # User ID to use (admin -> 1)
  user_id: 1
  # ENV var in which the DefectDojo API token will be provided 
  token_env_var: "DOJO_TOKEN"
  # Product ID in DefectDojo for the Docker images.
  docker_images_product_id: 1
hook:
  # Authentication token for the webhook (will need to match the one configured in Harbor)
  auth_token_env_var: "HOOK_AUTH_TOKEN"
  # Address to bind on
  host: 0.0.0.0
  # Port to bind on. If changed, modify Dockerfile as well
  port: 4444
  # Enable debug logging
  debug: False
```

Please **DO NOT** enable debug logging unless you are testing locally. The debug setting might print
to logs sensitive data such as vulnerability data, credentials used to access Harbor/DefectDojo etc.

### Prepare .env files

For docker-compose, one  *.env* file is used: `hardojo.env`.
Modify the template file with the actual credentials to be used. Make sure that file permissions
are set correctly so that only specific users can read this file.

### Build the image

From within the directory of the project, run (replace hardojo with the name you prefer):

`docker build -t hardojo .`

Now use the same name you have just chosen in the `docker-compose.yaml` file.

### Run

If everything has been configured correctly, you should be able to run the tool with:

`docker-compose up -d`

### Additional configuration

Additional configuration that is required to make it work includes:

* Pre-creating the **product** in Dojo (whose ID will need to be specified in the configuration).
* Configure the Webhook in Harbor with the correct auth header.

## A note on Harbor OIDC login

The process for getting Harbor API to work when OIDC is used can be found in [this
issue](https://github.com/goharbor/harbor/issues/10597).

Please note that in order for the application to be completely stateless, a new `id_token` is
requested from the OIDC provider every time a webhook is received. This behavior might be changed in
the future to optimize requests to OIDC provider.

## Performances

It was an intentional choice to offload some computation from DefectDojo to this tool. In
particular, every finding is pushed individually, rather than composing a file in a format
DefectDojo understands (e.g., Clair Scan format) and simply let Dojo parse it. On a non-powerful
hardware, the parsing call could take several minutes. If a 'scan-all' action in Harbor is
triggered, hundreds of images could be scanned at once, and DefectDojo can be overloaded.

Unpacking every Harbor vulnerability independently makes it easier to manage the load for
DefectDojo as 5 workers could process at any given time maximum 5 findings, rather than 5 scan
reports, that might range from 0 to thousands of findings and won't have a predictable load.

It is possible to tune the number of workers available, and from practical tests, 10 to 20 findings
per second worked well for Dojo running on a 4-core, 64GB RAM machine with SSD, with 100K+ findings.
