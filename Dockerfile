FROM golang:1.12.6
WORKDIR /go/src/github.com/open-policy-agent/opa
COPY ./ ./
RUN GOOS=linux go build -o /go/bin/opa
RUN go build -buildmode=plugin -o=/usr/local/plugins/ldap.so ./custom/ldap.go

FROM golang:1.12.6
COPY ./config.yml /config.yml
COPY --from=0 /go/bin/opa /opa
COPY --from=0 /usr/local/plugins /plugins
ENTRYPOINT ''
CMD /opa --plugin-dir /plugins run --server --addr 0.0.0.0:8080 --config-file /config.yml
EXPOSE 8080