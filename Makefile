.PHONY: rogue_mysql_server
rogue_mysql_server:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o rogue_mysql_server .
