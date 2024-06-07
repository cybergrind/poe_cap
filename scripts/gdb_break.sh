#!/usr/bin/env bash
set -e -x
DBG_INFO=/home/kpi/devel/github/poe_cap/poe_annotated.debug
PID=$(pgrep PathOfExileStea)
ADD_ON_START=(  )

# if not pid
if [ -z $PID ]; then
    echo "PathOfExileStea is not running"
    exit 1
fi

case $# in
    1)
        gdb -p $PID --batch --ex 'handle SIGUSR1 nostop noprint' --ex "$1" --ex "i b" --ex "c 20" --ex "i b" --ex "bt" --ex "info r" --ex 'x/10i $pc' --ex 'x /20x $rdx' --ex detach $DBG_INFO
        ;;
    2)
        gdb -p $PID --batch --ex $1 --ex "i b" --ex "c" --ex "stepi $2" --ex "info break" --ex "bt" --ex "info r" --ex detach $DBG_INFO
        ;;
    *)
        echo "Usage: $0 <command> [output_file]"
        ;;
esac
