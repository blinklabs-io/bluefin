FROM ghcr.io/blinklabs-io/go:1.21.4-1 AS build

WORKDIR /code
COPY . .
RUN make build

FROM cgr.dev/chainguard/glibc-dynamic AS bluefin
COPY --from=build /code/bluefin /bin/
ENTRYPOINT ["bluefin"]
