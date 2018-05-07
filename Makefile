VERSION = latest

build:
	GOOS=linux go build -ldflags="-s -w" .
	docker build -t swifty .

clean:
	rm swifty

.PHONY: release
release: build
	#@git tag -a v$(VERSION) -m "Release of version $(VERSION)"
	#@git push --tags
	@docker tag swifty crypto89/swifty:$(VERSION)
	@docker push crypto89/swifty:$(VERSION)
