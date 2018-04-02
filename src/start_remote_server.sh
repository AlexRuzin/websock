#!/bin/bash

SRC_DIR="`pwd`/src"
JSON_CONFIG="config.remote.server.json"

go test -v $SRC_DIR/atomic.go $SRC_DIR/pke.go $SRC_DIR/config.go $SRC_DIR/controller.go $SRC_DIR/websock_test.go -args -config $JSON_CONFIG 

