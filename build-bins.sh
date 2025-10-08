#!/bin/bash

# Exit early on first error
set -euo pipefail

# Build a container image called 'lucid-bins' based on the Dockerfile in this repo
docker build -t lucid-bins .

# Create a frozen instance of the container called 'lucid-cp'
docker create --name lucid-cp lucid-bins

# Remove any existing built binaries, remake dir
rm -rf bins && mkdir bins

# Copy the built binaries out of the frozen image into the bins dir
docker cp lucid-cp:/lucid/build/. ./bins

# Destroy the frozen instance
docker rm lucid-cp