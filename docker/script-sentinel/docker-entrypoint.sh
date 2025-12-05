#!/bin/bash
# Docker entrypoint for Script Sentinel XSIAM integration
# Supports both direct CLI mode and XSIAM wrapper mode

set -e

# Check if first argument is 'xsiam-wrapper'
if [ "$1" = "xsiam-wrapper" ]; then
    # XSIAM mode: use the wrapper script
    shift  # Remove 'xsiam-wrapper' from arguments
    exec python3 /app/xsiam_wrapper.py "$@"
elif [ "$1" = "analyze" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    # CLI mode: use sentinel.main directly
    exec python3 -m sentinel.main "$@"
else
    # For any other command (like 'which', 'python', etc.), execute it directly
    # This allows the Demisto build system to run verification commands
    exec "$@"
fi