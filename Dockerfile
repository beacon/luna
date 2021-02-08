FROM golang:1.15 as builder

WORKDIR /build
COPY . .
RUN make luna

FROM alpine:3.9

WORKDIR /opt/luna
COPY --from=builder /build/bin/luna ./luna
EXPOSE 8080
ENTRYPOINT ["/opt/luna/luna"]