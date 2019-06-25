FROM docker1.16801.com/ups/golang:1.11.9-alpine3.9
WORKDIR /go/src/github.com/open-policy-agent/opa
COPY ./ ./
RUN apt-get update && apt-get  build-dep  gcc
RUN GOOS=linux go build -o /go/bin/opa
RUN go build -buildmode=plugin -o=./custom/ldap.so ./custom/ldap.go

FROM docker1.16801.com/ups/golang:1.11.9-alpine3.9
COPY config.yml config.yml
COPY --from=0 /go/bin/opa /opa
COPY --from=0 /go/src/github.com/open-policy-agent/opa/custom /plugins
ENTRYPOINT /opa --plugin-dir /plugins
CMD run --server --addr 0.0.0.0:8080 --config-file config.yaml
EXPOSE 8080