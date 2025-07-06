build:
	go build -o ./bin/deenquestapi

run: build
	./bin/deenquestapi
