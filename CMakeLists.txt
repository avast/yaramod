##
## CMake build script for the yaramod.
##

cmake_minimum_required(VERSION 3.6)
project(yaramod CXX)

# Configurable options.
option(YARAMOD_TESTS    "Build tests for yaramod" OFF)
option(YARAMOD_DOCS     "Build doxygen documentation for yaramod" OFF)
option(YARAMOD_PYTHON   "Build Python extension" OFF)
option(YARAMOD_EXAMPLES "Build examples" OFF)

# Requirements.
include(GNUInstallDirs)
if(YARAMOD_DOC)
	find_package(Doxygen)
endif()

# Variables.
set(YARAMOD_DOC_DIR     "${PROJECT_SOURCE_DIR}/doc")
set(YARAMOD_SRC_DIR     "${PROJECT_SOURCE_DIR}/src")
set(YARAMOD_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
set(YARAMOD_SRC_BIN_DIR "${PROJECT_BINARY_DIR}/src")
set(YARAMOD_DEPS_DIR    "${PROJECT_SOURCE_DIR}/deps")
set(YARAMOD_PUBLIC_MODULES_DIR     "${PROJECT_SOURCE_DIR}/src/modules")
set(YARAMOD_PRIVATE_MODULES_DIR     "${PROJECT_SOURCE_DIR}/src/modules/private")

configure_file("${PROJECT_SOURCE_DIR}/modules_path.h.in" "${PROJECT_SOURCE_DIR}/include/yaramod/modules_path.h")

# Use C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

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
if(YARAMOD_DOCS)
	add_subdirectory(docs)
endif()

set(WRAP_MODULE_SOURCES
	${YARAMOD_SRC_DIR}/modules/module_elf.cpp
	${YARAMOD_SRC_DIR}/modules/module_macho.cpp
	${YARAMOD_SRC_DIR}/modules/module_cuckoo.cpp
	${YARAMOD_SRC_DIR}/modules/module_magic.cpp
	${YARAMOD_SRC_DIR}/modules/module_dotnet.cpp
	${YARAMOD_SRC_DIR}/modules/module_pe.cpp
	${YARAMOD_SRC_DIR}/modules/module_metadata.cpp
	${YARAMOD_SRC_DIR}/modules/module_dex.cpp
	${YARAMOD_SRC_DIR}/modules/module_cuckoo_deprecated.cpp
	${YARAMOD_SRC_DIR}/modules/module_math.cpp
	${YARAMOD_SRC_DIR}/modules/module_time.cpp
	${YARAMOD_SRC_DIR}/modules/module_hash.cpp
)

add_custom_command(
	OUTPUT ${WRAP_MODULE_SOURCES}
	COMMAND	python ${YARAMOD_SRC_DIR}/json_to_byte_array.py -i "${YARAMOD_PUBLIC_MODULES_DIR}/public" -o "${YARAMOD_PUBLIC_MODULES_DIR}"
	# WORKING_DIRECTORY
	# 	${CMAKE_CURRENT_SOURCE_DIR}
	COMMENT
		"Converting yaramod modules from JSON to byte arrays in .cpp files"
	# VERBATIM
)

add_custom_target(modules_wrapping ALL
	# WORKING_DIRECTORY
	# 	${CMAKE_CURRENT_BINARY_DIR}
	DEPENDS
		${WRAP_MODULE_SOURCES}
	VERBATIM
)
