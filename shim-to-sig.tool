#!/bin/sh

# shim-to-sig.tool - Extract OEM public key signature from GRUB shim file.
#
# Copyright (c) 2021, Michael Beaton. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-3-Clause
#

if [ -z "$1" ]; then
    echo "Usage: $0 {shimfile}"
    exit 1
fi

# require binutils and openssl
command -v objcopy >/dev/null 2>&1 || { echo >&2 "objcopy not found - please install binutils package."; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo >&2 "openssl not found - please install openssl package."; exit 1; }

tempfile=$(mktemp) || exit 1
certfile=$(mktemp) || exit 1

# make certain we have output file name, as objcopy will trash input file without it
if [ "x$tempfile" = "x" ]; then
    echo >&2 "Error creating tempfile!"
    exit 1
fi

# extract .vendor_cert section
objcopy -O binary -j .vendor_cert "$1" $tempfile || exit 1

if [ ! -s $tempfile ] ; then
    echo >&2 "No .vendor_cert section in $1."
    rm $tempfile
    rm $certfile
    exit 1
fi

# xargs just to trim white space
vendor_authorized_size=$(dd if=$tempfile ibs=1 skip=0 count=4 2>/dev/null | od -t u4 -An | xargs) || exit 1
vendor_authorized_offset=$(dd if=$tempfile ibs=1 skip=8 count=4 2>/dev/null | od -t u4 -An | xargs) || exit 1

# extract cert or db
dd if=$tempfile ibs=1 skip=$vendor_authorized_offset count=$vendor_authorized_size 2>/dev/null > $certfile || exit 1
rm $tempfile

# valid as single cert?
openssl x509 -noout -inform der -in $certfile 2>/dev/null

if [ $? -ne 0 ]; then
    # require efitools
    command -v sig-list-to-certs >/dev/null 2>&1 || { echo >&2 "sig-list-to-certs not found - please install efitools package."; exit 1; }

    certsdir=$(mktemp -d) || exit 1

    sig-list-to-certs $certfile $certsdir/shim 1>/dev/null || exit 1

    cp $certsdir/*.der $certfile 2>/dev/null

    if [ $? -ne 0 ]; then
        echo "Extracted multiple signing keys:"
        pwd=$(pwd)
        cd $certsdir
        ls -1 *.der
        cd $pwd

        cp $certsdir/*.der .

        rm -rf $certsdir

        rm $certfile

        exit 0
    fi

    rm -rf $certsdir
fi

# outfile name from cert CN
certname=$(openssl x509 -noout -subject -inform der -in $certfile | sed 's/^subject=.*CN\s=\s//' | sed 's/,.*//' | sed 's/\s//g') || exit 1
outfile="${certname}.pem"

openssl x509 -inform der -in $certfile -out $outfile || exit -1

rm $certfile

echo "Certificate extracted as ${outfile}."
