#!/bin/bash

# Command-line arguments
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <app_path> <output_dir>"
    exit 1
fi

app_path=$1
output_dir=$2   

# Check if output_dir exists, else create it 
if [ ! -d "$output_dir" ]; then
    mkdir -p "$output_dir"
fi

cd flowdroid_gen/flowdroid-cg
app_name=$(basename $app_path .apk)

# Measure execution time and RAM usage
start_time=$(date +%s.%N)
max_ram_kb=0

# Run the process in the background
# mvn exec:java -Dexec.mainClass="FlowDroidCG" -Dexec.args="$HOME/Android/Sdk/platforms $app_path $output_dir/$app_name" &
java -jar flowdroid_gen/flowdroid-cg/target/flowdroid-cg-1.0-SNAPSHOT.jar $HOME/Android/Sdk/platforms $app_path $output_dir
pid=$!

# Monitor RAM usage while the process is running
while kill -0 "$pid" 2>/dev/null; do
    current_ram_kb=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1}')
    if [[ $current_ram_kb -gt $max_ram_kb ]]; then
        max_ram_kb=$current_ram_kb
    fi
    sleep 1
done

wait "$pid"
end_time=$(date +%s.%N)

execution_time=$( echo "$end_time - $start_time" | bc -l )
max_ram_mb=$((max_ram_kb / 1024)) # Convert to MB

# Save app name, execution time, and RAM usage to stats.csv
# stats_file="$output_dir/stats.csv"
# if [ ! -f "$stats_file" ]; then
#     echo "App Name,Analysis Time (s),Max RAM Usage (MB)" > "$stats_file"
# fi
# echo "$app_name,$execution_time,$max_ram_mb" >> "$stats_file"
