#!/bin/bash

echo "🚀 Starting Zeroday Academy - Beginner Labs on port 5000..."
echo ""

# Kill any process on port 5000
lsof -ti:5000 | xargs kill -9 2>/dev/null || true

# Start beginner labs on port 5000 (LAB_LEVEL defaults to beginner)
PORT=5000 npm run dev
