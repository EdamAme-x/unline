# syntax=docker/dockerfile:1.7

FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" -o /out/unline ./cmd/unline

FROM build AS assets
ARG UNLINE_EXTENSION_ID=ophjlpahpchlmihnnnihgmmeilfjmjjc
ARG UNLINE_PROD_VERSION=120.0.6099.109
RUN /out/unline generate \
    --out /out/www \
    --cache /tmp/unline-cache \
    --extension-id "${UNLINE_EXTENSION_ID}" \
    --prod-version "${UNLINE_PROD_VERSION}"

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/unline /usr/local/bin/unline
COPY --from=assets --chown=nonroot:nonroot /out/www /app/www
ENV UNLINE_ADDR=0.0.0.0:8080
ENV UNLINE_ASSETS_DIR=/app/www
ENV UNLINE_ALLOWED_HOSTS=localhost,127.0.0.1,::1
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/unline"]
CMD ["serve"]
