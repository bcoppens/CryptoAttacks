#!/bin/bash
set -e
set -u

# Optional argument: number of make jobs
JOBS=${1:-2}

fetch()
{
	openssl=${1}
	commit=${2}

	echo "Setting up ${openssl} from commit ${commit}"...

	git clone git://git.openssl.org/openssl.git ${openssl}
	pushd ${openssl}
	git checkout ${commit}
	popd

	echo "... done"
}

build()
{
	openssl=$1
	
	echo "Building ${openssl}"
	
	pushd $openssl
	mkdir -p install/

	./config --prefix=${PWD}/install
	make -j ${JOBS} libcrypto.a
	# Do not actually make, since it triggers errors in man-page generation

	popd

	echo "... done"
}

echo "Setting up repositories..."
fetch vulnerable_openssl bbcf3a9b300bc8109bb306a53f6f3445ba02e8e9
# fetch fixed_openssl 992bdde62d2eea57bb85935a0c1a0ef0ca59b3da

echo "Building..."
build vulnerable_openssl
# build fixed_openssl

