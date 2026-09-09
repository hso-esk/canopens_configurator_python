#!/bin/bash

# Copyright (c) 2026
#
# Hochschule Offenburg, University of Applied Sciences
# Institute for reliable Embedded Systems
# and Communications Electronic (ivESK)
#
# This file is licensed as described in the "LICENSE" file
# included within the root folder of this work.

set -e

# Change to the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "${SCRIPT_DIR}"

VENV_DIR=".venv"

echo "Setting up Python virtual environment in ${VENV_DIR}..."

# Create virtual environment if it doesn't exist
if [ ! -d "${VENV_DIR}" ]; then
    echo "Creating virtual environment..."
    if ! python3 -m venv "${VENV_DIR}"; then
        echo "Failed to create virtual environment."
        echo "On Debian/Ubuntu systems, you might need to install the venv package:"
        echo "sudo apt-get install python3-venv (or python3.X-venv)"
        exit 1
    fi
else
    echo "Virtual environment already exists at ${VENV_DIR}."
fi

# Activate and install requirements
echo "Activating virtual environment and installing dependencies..."
source "${VENV_DIR}/bin/activate"

# Upgrade pip (optional but recommended)
python3 -m pip install --upgrade pip

# Install dependencies
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "Warning: requirements.txt not found in ${SCRIPT_DIR}."
fi

echo ""
echo "====================================================================="
echo "Setup complete!"
echo "To use the environment, activate it with the following command:"
echo "source ${VENV_DIR}/bin/activate"
echo "====================================================================="
