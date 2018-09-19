#!/bin/bash

mkdir artifacts
for arch in amd64 arm; do
	for os in darwin linux windows; do
		if [ "$arch" == "arm" ]; then
			if [ "$os" == "windows" ] || [ "$os" == "darwin" ]; then
				continue
			fi
		fi

		bin=ob1-scanner
		if [ "$os" == "windows" ]; then
			bin=ob1-scanner.exe
		fi

		GOOS=${os} GOARCH=${arch} go build -tags='netgo' -o artifacts/$arch/$os/$bin ./main.go
		if [ $? -ne 0 ]; then
			exit $?
		fi
	done
done
