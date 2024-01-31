BIN_NAME=iproxy
CGO_ENABLED=0

GOOS=android GOARCH=arm64
go build -o ${BIN_NAME}-${GOOS}-${GOARCH}

GOOS=linux GOARCH=amd64
go build -o ${BIN_NAME}-${GOOS}-${GOARCH}

GOOS=linux GOARCH=arm64
go build -o ${BIN_NAME}-${GOOS}-${GOARCH}

GOOS=windows GOARCH=amd64
go build -o ${BIN_NAME}.exe
