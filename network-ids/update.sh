#!/bin/bash
echo "Stopping NIDS..."
sudo systemctl stop nids.service

echo "Pulling latest code from GitHub..."
git pull origin main

# Uncomment if you use venv
# source venv/bin/activate
# pip install -r requirements.txt

echo "Restarting NIDS..."
sudo systemctl daemon-reload
sudo systemctl start nids.service

echo "Checking status..."
sudo systemctl status nids.service