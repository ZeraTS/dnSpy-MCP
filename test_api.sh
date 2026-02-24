#!/bin/bash

API_KEY="${DNSPY_API_KEY:-default-insecure-key-change-me}"
BASE_URL="http://localhost:9001"

echo "Testing dnspy MCP daemon..."

echo -e "\n[1] Health check"
curl -s $BASE_URL/health | jq .

echo -e "\n[2] Decompile (test)"
curl -s -X POST $BASE_URL/api/decompile \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/nonexistent/app.dll"
  }' | jq .

echo -e "\n[3] Analyze obfuscation (test)"
curl -s -X POST $BASE_URL/api/analyze-obfuscation \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/nonexistent/app.dll"}' | jq .

echo -e "\n[4] Extract class (test)"
curl -s -X POST $BASE_URL/api/extract-class \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/nonexistent/app.dll",
    "class_name": "System.String"
  }' | jq .

echo -e "\n[5] Unauthorized request (no key)"
curl -s -X POST $BASE_URL/api/decompile \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/path/to/app.dll"}' | jq .

echo -e "\nTests complete"
