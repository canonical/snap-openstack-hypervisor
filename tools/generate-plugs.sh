#!/usr/bin/env bash
# Regenerate tools/openstack-hypervisor.plugs.data from the store snap
# declaration of the openstack-hypervisor snap.
set -euo pipefail

cd "$(dirname "$0")/.."

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

snap known snap-declaration snap-name=openstack-hypervisor | \
  sed '/^$/Q' | \
  python3 -c 'import sys, yaml, json; print(json.dumps(yaml.safe_load(sys.stdin)["plugs"], indent=2))' \
  >"$tmp"

mv "$tmp" tools/openstack-hypervisor.plugs.data
trap - EXIT
