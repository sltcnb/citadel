#!/usr/bin/env bash
# Generate the gRPC Python stubs for the Collector service from the shared proto.
# Requires: pip install grpcio grpcio-tools
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
python -m grpc_tools.protoc \
  -I "$HERE/../../contracts" \
  --python_out="$HERE" \
  --grpc_python_out="$HERE" \
  "$HERE/../../contracts/collector.proto"
echo "Generated collector_pb2.py + collector_pb2_grpc.py in $HERE"
