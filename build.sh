#!/bin/bash

export PATH=$PATH:/home/github/aarch64-linux-android-4.9/bin
export ARCH=arm64
export SUBARCH=arm64
export CROSS_COMPILE=aarch64-linux-android-
make clean
make defconfig
make -j8
if [ $? -ne 0 ]; then
	echo "build failed."
	exit 1
fi
echo "build success."
mv $(pwd)/arch/arm64/boot/Image $(pwd)/../AnyKernel3/
mv $(pwd)/arch/arm64/boot/Image.gz $(pwd)/../AnyKernel3/
mv $(pwd)/arch/arm64/boot/Image.gz-dtb $(pwd)/../AnyKernel3/

