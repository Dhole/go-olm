#!/bin/sh

CGO_CFLAGS="-I/home/dev/git/olm/include/" CGO_LDFLAGS="-L/home/dev/git/olm/build/" go test -v
