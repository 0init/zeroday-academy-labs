#!/bin/bash

echo "🎯 Starting Zeroday Academy - Intermediate Labs..."

# Check if build exists
if [ ! -f "dist/intermediate/index.js" ]; then
  echo "❌ Intermediate build not found. Building now..."
  node build-intermediate.js
fi

echo "🏃 Starting Intermediate Labs server..."
NODE_ENV=production PORT=5000 node dist/intermediate/index.js