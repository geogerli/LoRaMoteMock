rem set GOARCH=386
set CGO_ENABLED=0
go build -ldflags "-H windowsgui"