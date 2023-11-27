FROM golang:1.21.2-alpine

MAINTAINER Knut Ahlers <knut@ahlers.me>

ADD . /go/src/github.com/Luzifer/grafana-proxy
WORKDIR /go/src/github.com/Luzifer/grafana-proxy

RUN set -ex \
 # && sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories \
 && apk update && apk upgrade \
 && apk add --update git \
 # && export GOPROXY=https://proxy.golang.com.cn,direct \
 && go mod tidy \
 && go install -ldflags "-X main.version=$(git describe --tags || git rev-parse --short HEAD || echo dev)" \
 && apk del --purge git

EXPOSE 3001

ENTRYPOINT ["/go/bin/grafana-proxy"]
CMD ["--listen", "0.0.0.0:3001"]
