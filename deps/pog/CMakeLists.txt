include(ExternalProject)
include(GNUInstallDirs)

find_package(Threads REQUIRED)

if(CMAKE_C_COMPILER)
   set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
   set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

set(POG_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/pog-install)
# Set include directories.
set(POG_INCLUDE_DIR ${POG_INSTALL_DIR}/include)

ExternalProject_Add(pog-project
   URL https://github.com/metthal/pog/archive/v0.2.1.zip
   URL_HASH SHA256=92b0ed8fcc3b6b5f3c6ccc4b6236154f1cac12d65285388eea95e8d8078e247d
   DOWNLOAD_NAME pog.zip
   CMAKE_ARGS
      # This does not work on MSVC, but may be useful on Linux.
      -DCMAKE_BUILD_TYPE=Release
      -DCMAKE_INSTALL_PREFIX=${POG_INSTALL_DIR}
      -DPOG_DOWNLOAD_RE2=ON
      -DPOG_DOWNLOAD_FMT=ON
      -DPOG_PIC=ON
      # Force the use of the same compiler as used to build the top-level
      # project. Otherwise, the external project may pick up a different
      # compiler, which may result in link errors.
      "${CMAKE_C_COMPILER_OPTION}"
      "${CMAKE_CXX_COMPILER_OPTION}"
   # Disable the update step.
   UPDATE_COMMAND ""
   LOG_DOWNLOAD ON
   LOG_CONFIGURE ON
   LOG_BUILD ON
)

add_library(pog INTERFACE)
target_link_libraries(pog INTERFACE ${POG_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(pog INTERFACE ${POG_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(pog INTERFACE Threads::Threads)
target_include_directories(pog INTERFACE ${POG_INCLUDE_DIR})
target_include_directories(pog INTERFACE ${POG_INCLUDE_DIR}/pog)
add_dependencies(pog pog-project)
