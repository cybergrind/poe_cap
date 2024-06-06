#!/usr/bin/env bash
DBG_INFO=/home/kpi/devel/github/poe_cap/poe_annotated.debug
PID=$(pgrep PathOfExileStea)

# if not pid
if [ -z $PID ]; then
    echo "PathOfExileStea is not running"
    exit 1
fi

case $# in
    1)
        gdb -p $PID --batch --ex $1 --ex "i b" --ex "c" --ex "info break" --ex "bt" --ex "info r" --ex detach $DBG_INFO
        ;;
    2)
        gdb -p $PID --batch --ex $1 --ex "i b" --ex "c" --ex "stepi $2" --ex "info break" --ex "bt" --ex "info r" --ex detach $DBG_INFO
        ;;
    *)
        echo "Usage: $0 <command> [output_file]"
        ;;
esac
