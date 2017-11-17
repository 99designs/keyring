#!/bin/bash
set -eu

go get github.com/kardianos/govendor
govendor status
