#!/bin/sh -xe
cd $(dirname $0)
for arch in amd64
do
	for os in linux darwin windows
	do
		GOOS=$os GOARCH=$arch go build -o mackerel-plugin-httpstat.$os.$arch .
	done
done
for arch in arm arm64
	do
	for os in linux
	do
		GOOS=$os GOARCH=$arch go build -o mackerel-plugin-httpstat.$os.$arch .
	done
done
