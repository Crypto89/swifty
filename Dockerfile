FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY ./swifty /usr/bin/swifty
ENTRYPOINT ["swifty"]
