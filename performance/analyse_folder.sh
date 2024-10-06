dir="$1"
if [[ -z "$dir" ]]; then 
    echo "No directory specified." 
    exit 1
fi
if [[ -f "$dir/comp_output.log" ]]; then
    source /home/dc/ZT_RKE2/module/venv/bin/activate && python3 analyse_log.py $dir/py.log -a $dir/mal.log -c $dir/sample_output.log -n $dir/comp_output.log
else
    source /home/dc/ZT_RKE2/module/venv/bin/activate && python3 analyse_log.py $dir/py.log -a $dir/mal.log -c $dir/sample_output.log
fi
