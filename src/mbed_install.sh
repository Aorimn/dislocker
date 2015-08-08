#!/bin/bash

if brew info polarssl |head -1 |grep -q 2.0.0
then
	git clone https://github.com/ARMmbed/mbedtls.git
	cd mbedtls
	git checkout mbedtls-2.0.0
	git cherry-pick -n --strategy=recursive -Xours 6f42417ba8dd28fa77fd08d42d73c87a0253f93e
	cmake .
	make VERBOSE=1
	make install
	cd ..
	rm -fr mbedtls
else
	brew install -v polarssl
fi
