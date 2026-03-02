#!/bin/bash

if [[ ! -v JWT ]]; then
  echo "Set 'JWT' environment var with you current JWT"
  exit -1
fi

HOST="192.168.60.10"
PORT=4568
URL_HOST="${HOST}:${PORT}"

echo "Deleting file 'C:\temp\FOOBAR.txt' on the DES"

curl --path-as-is -i -s -k -X $'DELETE' \
    -H "Host: ${URL_HOST}" -H $'Accept: */*' -H $'Accept-Encoding: gzip, deflate, br' -H $'Connection: keep-alive' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0' -H "Authorization: Bearer ${JWT}" -H $'Content-Length: 62' -H $'Content-Type: application/json' \
    --data-binary $'{\"TraceFiles\":[{\"computer\":\"\",\"name\":\"C:\\\\temp\\\\FOOBAR.txt\"}]}' \
    "https://${URL_HOST}/api/administration/traceFiles/traces"
