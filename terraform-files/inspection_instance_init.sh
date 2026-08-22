#!/bin/bash
dnf install -y git gcc python3.11 pip
git clone https://github.com/AnthoBalitrand/geneve-router.git
cd geneve-router || exit
pip install -r requirements.txt
python3 main.py -t -l info
