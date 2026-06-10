#!/bin/bash

# Define the path to the version file
VERSION_FILE="version.txt"

# Check if the version file exists
if [ ! -f "$VERSION_FILE" ]; then
        echo "Version file not found!"
        exit 1
fi

# Read the current image name and version
FULL_IMAGE_VERSION=$(cat "$VERSION_FILE")

# Use read -a to split the image name and version
IFS=':' read -ra IMAGE_NAME_VERSION <<<"$FULL_IMAGE_VERSION"
IMAGE_NAME="${IMAGE_NAME_VERSION[0]}"
CURRENT_VERSION="${IMAGE_NAME_VERSION[1]}"

# Increment the version
# This is a simple increment; you might need a more sophisticated approach
# depending on your versioning scheme (e.g., semantic versioning)
NEW_VERSION=$(echo "$CURRENT_VERSION" | awk -F. '{print $1"."$2"."$3+1}')

# Update the version file with the new version
echo "${IMAGE_NAME}:${NEW_VERSION}" >"$VERSION_FILE"

# Build the Docker image with the new version
docker build -t "${IMAGE_NAME}:${NEW_VERSION}" .

# Output the new version
echo "Built Docker image: ${IMAGE_NAME}:${NEW_VERSION}"
