set BIN_NAME=iproxy
set CGO_ENABLED=0

set GOOS=android
set GOARCH=arm64
go build -o %BIN_NAME%-%GOOS%-%GOARCH%

set GOOS=linux
set GOARCH=amd64
go build -o %BIN_NAME%-%GOOS%-%GOARCH%

set GOOS=linux
set GOARCH=arm64
go build -o %BIN_NAME%-%GOOS%-%GOARCH%

set GOOS=windows
set GOARCH=amd64
go build -o %BIN_NAME%.exe