# Build and Runtime Validation

Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Linux Build
- `cmake -S . -B build/full -G Ninja`
- `cmake --build build/full`
- `ctest --test-dir build/full`

## Runtime Smoke Test
- `timeout 2 ./build/full/ubuntu/wsl_monitor`

All commands completed without errors, confirming the tree builds cleanly and the Ubuntu daemon starts.
