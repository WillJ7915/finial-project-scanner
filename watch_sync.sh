#!/bin/bash

# Array of source-target pairs
declare -A WATCH_PAIRS
WATCH_PAIRS["/home/codio/workspace/Network_Scan_Script/Active_Script/will_gen_scan.sh"]="/home/codio/workspace/Network_Scan_Script/Repository/final-project-scanner"
WATCH_PAIRS["/home/codio/workspace/Network_Scan_Script/Active_Script/watch_sync.sh"]="/home/codio/workspace/Network_Scan_Script/Repository/final-project-scanner/watch_sync.sh"

# Extract source paths for inotifywait
WATCHED_FILES=("${!WATCH_PAIRS[@]}")

# Convert array into inotifywait arguments
inotifywait -m -e close_write "${WATCHED_FILES[@]}" --format '%w%f' | while read MODIFIED_FILE
do
    TARGET_FILE="${WATCH_PAIRS["$MODIFIED_FILE"]}"

    if [ -n "$TARGET_FILE" ]; then
        mkdir -p "$(dirname "$TARGET_FILE")"
        cp "$MODIFIED_FILE" "$TARGET_FILE"
        echo "Synced: $MODIFIED_FILE → $TARGET_FILE"
    fi
done
