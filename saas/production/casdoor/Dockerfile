FROM --platform=$BUILDPLATFORM node:20.20.1-bookworm-slim@sha256:17281e8d1dc4d671976c6b89a12f47a44c2f390b63a989e2e327631041f544fd AS frontend
WORKDIR /web
COPY web/package.json web/yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 300000
COPY web/ ./
RUN NODE_OPTIONS=--max-old-space-size=4096 yarn build

FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS backend
WORKDIR /src
ENV GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . ./
RUN CGO_ENABLED=0 go test ./object -run '^TestStbz' -count=1
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags='-s -w -buildid= -X github.com/casdoor/casdoor/util.Version=v4.25.0-stbz.3 -X github.com/casdoor/casdoor/util.CommitId=528a0213f01caf70b9f41009cbf7b2f67bdd67ec -X github.com/casdoor/casdoor/util.BuildType=stbz' \
    -o /out/server .

FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
ARG PRODUCT_REVISION
LABEL org.opencontainers.image.title="Shengtian Banzi customer identity" \
      org.opencontainers.image.version="v4.25.0-stbz.3" \
      org.opencontainers.image.source="https://github.com/casdoor/casdoor" \
      org.opencontainers.image.revision="528a0213f01caf70b9f41009cbf7b2f67bdd67ec" \
      com.shengtianbanzi.product-revision="$PRODUCT_REVISION"
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=backend /usr/share/zoneinfo/ /usr/share/zoneinfo/
COPY --from=backend /out/server /server
COPY --from=backend /src/swagger/ /swagger/
COPY --from=backend /src/LICENSE /LICENSE.casdoor
COPY --from=backend /src/stbz-source-receipt.json /stbz-source-receipt.json
COPY --from=frontend /web/build/ /web/build/
RUN mkdir -p /conf /data /logs && chown 65532:65532 /data /logs
WORKDIR /
USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["/server"]
