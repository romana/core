#!/bin/sh
body=$1
echo $body | curl -H 'content-type: application/json' -d @- -X POST http://localhost:9630/
