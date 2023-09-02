# FROM ghcr.io/blinklabs-io/go:1.19.12-1 AS build
FROM cgr.dev/chainguard/go AS build

WORKDIR /code
COPY . .
RUN make build

FROM cgr.dev/chainguard/glibc-dynamic AS bluefin
COPY --from=build /code/bluefin /bin/
ENTRYPOINT ["bluefin"]
