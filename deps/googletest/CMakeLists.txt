cmake_minimum_required(VERSION 3.6)

find_package(Threads REQUIRED)

include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(googletest
	URL https://github.com/google/googletest/archive/58d77fa8070e8cec2dc1ed015d66b454c8d78850.zip
	URL_HASH SHA256=ab78fa3f912d44d38b785ec011a25f26512aaedc5291f51f3807c592b506d33a
	CMAKE_ARGS
		# This does not work on MSVC, but is useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		# Without this, googletest's CMakeLists.txt replaces "/MD" (dynamic run-time) with "-MT" (static runtime).
		# Default config for most applications is "/MD", so this will cause problems if linked with "-MT" googletest.
		# https://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx
		-Dgtest_force_shared_crt=ON
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

# Set include directories.
ExternalProject_Get_Property(googletest source_dir)
set(GTEST_INCLUDE_DIR ${source_dir}/googletest/include)
set(GMOCK_INCLUDE_DIR ${source_dir}/googlemock/include)

# Add libraries.
ExternalProject_Get_Property(googletest binary_dir)

if(MSVC)
	set(DEBUG_DIR "Debug/")
	set(RELEASE_DIR "Release/")
	set(DEBUG_LIB_SUFFIX "d")
endif()

add_library(gtest INTERFACE)
target_link_libraries(gtest INTERFACE debug ${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_link_libraries(gtest INTERFACE optimized ${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_include_directories(gtest SYSTEM INTERFACE ${GTEST_INCLUDE_DIR})
add_dependencies(gtest googletest)

add_library(gtest_main INTERFACE)
target_link_libraries(gtest_main INTERFACE debug ${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest_main${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_link_libraries(gtest_main INTERFACE optimized ${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest_main${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_link_libraries(gtest_main INTERFACE gtest)
target_include_directories(gtest_main SYSTEM INTERFACE ${GTEST_INCLUDE_DIR})
add_dependencies(gtest_main googletest)

add_library(gmock INTERFACE)
target_link_libraries(gmock INTERFACE debug ${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_link_libraries(gmock INTERFACE optimized ${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_link_libraries(gmock INTERFACE gtest)
target_include_directories(gmock SYSTEM INTERFACE ${GTEST_INCLUDE_DIR} ${GMOCK_INCLUDE_DIR})
add_dependencies(gmock googletest)

add_library(gmock_main INTERFACE)
target_link_libraries(gmock_main INTERFACE debug ${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock_main${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_link_libraries(gmock_main INTERFACE optimized ${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock_main${CMAKE_STATIC_LIBRARY_SUFFIX} Threads::Threads)
target_link_libraries(gmock_main INTERFACE gmock)
target_include_directories(gmock_main SYSTEM INTERFACE ${GTEST_INCLUDE_DIR} ${GMOCK_INCLUDE_DIR})
add_dependencies(gmock_main googletest)
