FROM registry.access.redhat.com/ubi9/go-toolset:latest as builder
COPY --chown=1001:1001 ./ /src
WORKDIR /src
RUN go build

FROM registry.access.redhat.com/ubi9/ubi-micro:latest
COPY --chown=1001:1001 --from=builder /src/authfox /authfox
COPY --chown=1001:1001 --from=builder /src/swagger /swagger
USER 1001
ENTRYPOINT [ "/authfox" ]
