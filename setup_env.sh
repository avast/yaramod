#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd -P)"
VIRTUALENV_DIR="${SCRIPT_DIR}/env"

if [ -z ${PYTHON_EXECUTABLE} ]; then
	PYTHON_EXECUTABLE=python3
fi

${PYTHON_EXECUTABLE} -m venv "${VIRTUALENV_DIR}"
