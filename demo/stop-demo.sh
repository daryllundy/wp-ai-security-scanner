#!/bin/bash

# WordPress AI Security Scanner Demo Stop Script

echo "Stopping WordPress AI Security Scanner Demo Environment"
echo "========================================================"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running."
    exit 1
fi

# Check for -v flag to remove volumes
REMOVE_VOLUMES=false
if [ "$1" = "-v" ] || [ "$1" = "--volumes" ]; then
    REMOVE_VOLUMES=true
fi

echo "Stopping Docker containers..."

if [ "$REMOVE_VOLUMES" = true ]; then
    echo "Removing volumes (all data will be deleted)..."
    docker-compose down -v
    echo ""
    echo "Demo environment stopped and all data removed."
else
    docker-compose down
    echo ""
    echo "Demo environment stopped."
    echo "Data volumes preserved. Use './stop-demo.sh -v' to remove all data."
fi

echo ""
echo "To restart: ./start-demo.sh"
