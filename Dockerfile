FROM golang:buster AS builder
WORKDIR /go/src/Hardojo
# Get packages dependencies
RUN go get -d -v github.com/sirupsen/logrus gopkg.in/yaml.v2
# Copy main file
COPY hardojo.go /go/src/Hardojo/
# Copy packages
COPY pkg/ /go/src/Hardojo/pkg
# Compile the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o hardojo .
# Add user (so that we can copy /etc/passwd and /etc/group)
RUN groupadd -r hardojo && useradd --no-log-init -r -g hardojo hardojo


# Start from scratch - This will be the final image
FROM scratch

# Copy CA certificates to be able to connect to HTTPS sites.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# COPY /etc/passwd and /etc/group to have hardojo user in new image
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /go/src/Hardojo/hardojo /hardojo

# Drop privileges, don't run as root
USER hardojo:hardojo

EXPOSE 4444
ENTRYPOINT ["/hardojo", "-config", "/app/config.yaml"]

