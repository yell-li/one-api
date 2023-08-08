FROM node:16 as builder

WORKDIR /build
COPY ./web .
COPY ./VERSION .
RUN npm install
RUN REACT_APP_VERSION=$(cat VERSION) npm run build

FROM golang AS builder2

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

FROM alpine

RUN apk update \
    && apk upgrade \
    && apk add --no-cache ca-certificates tzdata \
    && update-ca-certificates 2>/dev/null || true

COPY --from=builder2 /build/one-api /
COPY ./.env /
EXPOSE 3000
WORKDIR /
ENTRYPOINT ["/one-api"]
