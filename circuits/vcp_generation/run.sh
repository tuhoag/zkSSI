#!/usr/bin/env bash
set -e
nargo prove &
pid=$!

# logfile=$(mktemp -t memory.log.XXXX)
start=$(date +%s)

# get the process' memory usage and run until `ps` fails which it will do when
# the pid cannot be found any longer

while mem=$(ps -o rss= -p "$pid"); do
    time=$(date +%s)

    # print the time since starting the program followed by its memory usage
    printf "%d %s\n" $((time-start)) "$mem"
    # printf "%d %s\n" $((time-start)) "$mem" >> "$logfile"

    # sleep for a tenth of a second
    sleep .1
done

printf "Find the log at %s\n" "$logfile"