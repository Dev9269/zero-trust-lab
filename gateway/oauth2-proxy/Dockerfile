FROM --platform=linux/amd64 ubuntu:24.04 AS ubuntu
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget && rm -rf /var/lib/apt/lists/*

FROM quay.io/oauth2-proxy/oauth2-proxy:v7.8.2 AS upstream
FROM ubuntu
COPY --from=upstream /bin/oauth2-proxy /bin/oauth2-proxy
ENTRYPOINT ["/bin/oauth2-proxy"]
