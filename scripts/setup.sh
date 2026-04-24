#!/bin/bash
set -e

# System dependencies
sudo apt update
sudo apt install -y make

# Python environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
