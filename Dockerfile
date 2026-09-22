FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/gateway ./cmd/gateway

FROM alpine:3.22
RUN addgroup -S gateway && adduser -S gateway -G gateway
COPY --from=build /out/gateway /gateway
USER gateway
EXPOSE 8081
ENTRYPOINT ["/gateway"]