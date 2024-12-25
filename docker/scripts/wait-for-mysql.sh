#!/bin/sh
# wait-for-mysql.sh


sleep 30

>&2 echo "Mysql is up - executing command"
exec "$@"
