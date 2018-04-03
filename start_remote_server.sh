#!/bin/bash

SRC_DIR="`pwd`"
JSON_CONFIG="`pwd`/../config/config.remote.server.json"

go clean
go build

go test -v $SRC_DIR/client.go $SRC_DIR/server.go $SRC_DIR/pke.go $SRC_DIR/config.go $SRC_DIR/shared.go $SRC_DIR/websock_test.go -args -config $JSON_CONFIG 

