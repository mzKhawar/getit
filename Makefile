build:
	go build -o ./bin/getitapi

run: build
	./bin/getitapi
