#!/bin/sh
body=`echo $1 | cut -d'=' -f2`
echo $body | curl -H 'content-type: application/json' -d @- -X DELETE http://localhost:9630/
