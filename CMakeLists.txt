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

# Add CMake module path.
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Requirements.
include(GNUInstallDirs)
if(YARAMOD_DOC)
	find_package(Doxygen)
endif()
find_package(Filesystem)

# Variables.
set(YARAMOD_DOC_DIR     "${PROJECT_SOURCE_DIR}/doc")
set(YARAMOD_SRC_DIR     "${PROJECT_SOURCE_DIR}/src")
set(YARAMOD_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")
set(YARAMOD_SCRIPTS_DIR "${PROJECT_SOURCE_DIR}/scripts")
set(YARAMOD_SRC_BIN_DIR "${PROJECT_BINARY_DIR}/src")
set(YARAMOD_DEPS_DIR    "${PROJECT_SOURCE_DIR}/deps")
set(YARAMOD_MODULES_DIR     "${PROJECT_SOURCE_DIR}/modules")
set(YARAMOD_MODULES_GENERATED_DIR     "${YARAMOD_INCLUDE_DIR}/yaramod/types/modules/generated")
set(WRAP_MODULE_SOURCES
	${YARAMOD_MODULES_GENERATED_DIR}/module_cuckoo_deprecated_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_cuckoo_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_dex_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_dotnet_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_elf_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_hash_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_macho_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_magic_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_math_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_pe_generated.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_list.h
	${YARAMOD_MODULES_GENERATED_DIR}/module_time_generated.h
)

file(MAKE_DIRECTORY ${YARAMOD_MODULES_GENERATED_DIR})

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

# Command that creates files in ${WRAP_MODULE_SOURCES}
add_custom_command(
	OUTPUT ${WRAP_MODULE_SOURCES}
	# Create .h modules from .json modules
	COMMAND	python ${YARAMOD_SCRIPTS_DIR}/json_to_array.py -i "${YARAMOD_MODULES_DIR}" -o "${YARAMOD_MODULES_GENERATED_DIR}"
	COMMENT
		"Converting yaramod modules from JSON to byte arrays in .cpp files"
)

# Target depending on creation of modules ${WRAP_MODULE_SOURCES} by the command 
add_custom_target(modules_wrapping ALL
	DEPENDS
		${WRAP_MODULE_SOURCES}
	VERBATIM
)
add_dependencies(yaramod modules_wrapping)
