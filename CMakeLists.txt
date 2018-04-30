##
## CMake build script for the yaramod.
##

cmake_minimum_required(VERSION 3.6)
project(yaramod CXX)

# Configurable options.
option(YARAMOD_TESTS    "Build tests for yaramod" OFF)
option(YARAMOD_DOC      "Build doxygen documentation for yaramod" OFF)
option(YARAMOD_PYTHON   "Build Python extension" OFF)
option(YARAMOD_EXAMPLES "Build examples" OFF)

# Requirements.
include(GNUInstallDirs)
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)
if(YARAMOD_DOC)
	find_package(Doxygen)
endif()

# Variables.
set(YARAMOD_DOC_DIR     "${PROJECT_SOURCE_DIR}/doc")
set(YARAMOD_SRC_DIR     "${PROJECT_SOURCE_DIR}/src")
set(YARAMOD_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
set(YARAMOD_SRC_BIN_DIR "${PROJECT_BINARY_DIR}/src")
set(YARAMOD_DEPS_DIR    "${PROJECT_SOURCE_DIR}/deps")

# Use C++14.
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable all compiler warnings.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

# Always build position independent code.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Subdirectories.
add_subdirectory(deps)
add_subdirectory(src)
if(YARAMOD_TESTS)
	add_subdirectory(tests)
endif()
if(YARAMOD_DOC)
	add_subdirectory(doc)
endif()
