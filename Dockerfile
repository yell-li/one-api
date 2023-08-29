FROM reg.xthklocal.cn/xthk-library/node:16.20.1-debian10 as builder

WORKDIR /build
COPY web/package.json .
RUN npm install
COPY ./web .
COPY ./VERSION .
RUN DISABLE_ESLINT_PLUGIN='true' REACT_APP_VERSION=$(cat VERSION) npm run build

FROM reg.xthklocal.cn/xthk-library/go:1.18-debian11 AS builder2

ENV GO111MODULE=on \
    CGO_ENABLED=1 \
    GOOS=linux

WORKDIR /build
COPY . .
COPY --from=builder /build/build ./web/build
RUN go env -w GOPROXY=https://goproxy.cn,direct \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on \
   && go mod download
RUN go build -ldflags "-s -w -X 'one-api/common.Version=$(cat VERSION)' -extldflags '-static'" -o one-api

FROM reg.xthklocal.cn/xthk-library/alpine:3.18.2


ENV XTHK_CODE_ROOT=/var/www/code/app
COPY --from=builder2 /build/one-api  /var/www/code/app/
COPY ./.env /var/www/code/app/
EXPOSE 3000
WORKDIR /var/www/code/app
