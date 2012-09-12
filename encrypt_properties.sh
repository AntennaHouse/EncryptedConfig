#!/bin/bash

BASEDIR=`dirname $0`

printUsage(){
	echo "Usage: `basename $0` inputfile.properties" >&2
	exit 1
}

if [ "$#" -ne "1" -o "x$1" = "x" ]
then
	printUsage
fi

gpg \
	--no-default-keyring \
	--keyring "$BASEDIR/key.pub" \
	--secret-keyring "$BASEDIR/key.priv" \
	--cipher-algo AES128 \
	-vv -o "$1.encrypted" --yes -e "$1"

