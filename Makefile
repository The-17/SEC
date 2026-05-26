.PHONY: all build test fmt lint clean install status adversarial

BINARY_NAME=sec

all: build test

build:
	go build -o $(BINARY_NAME) ./cmd/sec

test:
	go test -v ./...

fmt:
	go fmt ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY_NAME)
	rm -f jti_test.db err.log err_*.log out_*.log
	rm -rf C:\\Users\\steppa\\AppData\\Local\\Temp\\sec-test-home-*
	rm -rf C:\\Users\\steppa\\AppData\\Local\\Temp\\sec-test-build-*

install:
	go install ./cmd/sec

status: build
	./$(BINARY_NAME) status

adversarial:
	./adversarial_test.sh
