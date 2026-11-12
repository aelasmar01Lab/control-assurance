# Builds the cca binary and runs it as an unprivileged user.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/cca ./cmd/cca

FROM alpine:3.22
RUN adduser -D -u 10001 cca && mkdir -p /var/lib/cca/evidence && chown -R cca /var/lib/cca
USER cca
ENV CCA_EVIDENCE_DIR=/var/lib/cca/evidence
COPY --from=build /out/cca /usr/local/bin/cca
EXPOSE 8080
ENTRYPOINT ["cca"]
