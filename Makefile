.PHONY: lint fmt test

lint:
	go vet ./...
	$(shell go env GOPATH)/bin/golangci-lint run ./...

fmt:
	$(shell go env GOPATH)/bin/goimports -w .
	$(shell go env GOPATH)/bin/golines -m 80 -w .

test:
	go test -count=1 ./...
