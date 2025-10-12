#!/bin/bash

echo "🎯 Starting Zeroday Academy - Intermediate Labs on port 8000..."
echo ""

# Kill any process on port 8000
lsof -ti:8000 | xargs kill -9 2>/dev/null || true

# Start intermediate labs on port 8000
PORT=8000 LAB_LEVEL=intermediate npm run dev
