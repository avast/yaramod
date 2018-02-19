#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")"; pwd -P)"
VIRTUALENV_DIR="${SCRIPT_DIR}/env"

SED=$([[ $(command -v gsed) ]] && echo -n "gsed" || echo -n "sed")

if [ -z ${PYTHON_EXECUTABLE} ]; then
	if [[ $(command -v python3) ]]; then
		PYTHON_EXECUTABLE=python3
	elif [[ $(command -v python) ]]; then
		PYTHON_VERSION_STR=$(python --version 2>&1 | $SED -r 's/^Python //g')
		IFS='.' read -r -a PYTHON_VERSION <<< ${PYTHON_VERSION_STR}
		if [ ${PYTHON_VERSION[0]} -lt 3 ]; then
			echo "Required Python version is at least 3.0 (yours is ${PYTHON_VERSION_STR}). Please install appropriate version of Python or set PYTHON_EXECUTABLE in your environment to your Python interpreter." >&2
			exit 1
		fi
		PYTHON_EXECUTABLE=python
	else
		echo "Could not locate Python with any known name (python3, python). Make sure you have Python 3+ installed and set PYTHON_EXECUTABLE in your environment to your Python interpreter." >&2
		exit 1
	fi
else
	PYTHON_VERSION_STR=$(${PYTHON_EXECUTABLE} --version 2>&1 | $SED -r 's/^Python //g')
	IFS='.' read -r -a PYTHON_VERSION <<< ${PYTHON_VERSION_STR}
	if [ ${PYTHON_VERSION[0]} -lt 3 ]; then
		echo "Required Python version is at least 3.0 (yours is ${PYTHON_VERSION_STR}). Please install appropriate version of Python or set PYTHON_EXECUTABLE in your environment to your Python interpreter." >&2
		exit 1
	fi
fi

${PYTHON_EXECUTABLE} -m venv "${VIRTUALENV_DIR}"

source "${SCRIPT_DIR}/use_env.sh"
pip install -r "${SCRIPT_DIR}/requirements.txt"
