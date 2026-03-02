#!/bin/bash

if [[ ! -v JWT ]]; then
  echo "Set 'JWT' environment var with you current JWT"
  exit -1
fi

HOST="192.168.60.10"
PORT=4568
URL_HOST="${HOST}:${PORT}"
DES_NAME="packer-win2019.pentest.lab"

echo "Listing folder content of DES (name: ${DES_NAME}) - C:\temp"

curl --path-as-is -i -s -k -X $'GET' \
    -H "Host: ${URL_HOST}" -H $'Accept: */*' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0' -H "Authorization: Bearer ${JWT}" \
    "https://${URL_HOST}/api/administration/infrastructure/diagnosticFileListing/${DES_NAME}/1/C%3A%5Ctemp"