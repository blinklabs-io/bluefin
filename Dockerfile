FROM ghcr.io/blinklabs-io/go:1.23.5-1 AS build

WORKDIR /code
COPY . .
RUN make build

FROM cgr.dev/chainguard/glibc-dynamic AS bluefin
COPY --from=build /code/bluefin /bin/
# Create data dir owned by container user and use it as default dir
VOLUME /data
WORKDIR /data
ENTRYPOINT ["bluefin"]
