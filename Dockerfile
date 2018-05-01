FROM alpine:latest
COPY ./swifty /usr/bin/swifty
ENTRYPOINT ["swifty"]
