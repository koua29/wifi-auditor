#!/bin/bash
cd "$(dirname "$0")"
python3 gui_server.py &
sleep 1
open http://127.0.0.1:8777
wait
