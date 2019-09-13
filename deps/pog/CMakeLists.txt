include(ExternalProject)

if(CMAKE_C_COMPILER)
   set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
   set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

if(false)                                                                      #TODO POG_LOCAL_DIR
   message(STATUS "pog: using local pog directory.")

   ExternalProject_Add(pog-project                                                     #TODO pog-project
      DOWNLOAD_COMMAND ""
      SOURCE_DIR "${POG_LOCAL_DIR}"
      CMAKE_ARGS
         # This does not work on MSVC, but may be useful on Linux.
         -DCMAKE_BUILD_TYPE=Release
         # Force the use of the same compiler as used to build the top-level
         # project. Otherwise, the external project may pick up a different
         # compiler, which may result in link errors.
         "${CMAKE_C_COMPILER_OPTION}"
         "${CMAKE_CXX_COMPILER_OPTION}"
         # Disable unused options.
         -DPOG_DOWNLOAD_FMT=ON
         -DPOG_DOWNLOAD_RE2=ON
         -DPOG_PIC=ON
      # Disable the update step.
      UPDATE_COMMAND ""
      # Disable the install step.
      INSTALL_COMMAND ""
   )
   force_configure_step(pog-project)
else()
   message(STATUS "pog: using remote pog revision.")

   ExternalProject_Add(pog-project
      URL https://github.com/metthal/pog/archive/master.zip
      URL_HASH SHA256=5e5e4a38a6a70e6dcdfed949eebd42e76c3173ebca60f8bfaee0c8ad84e576a6    #TODO: Je ok ze jde o sha256('https://github.com/metthal/pog/archive/master.zip')?
      DOWNLOAD_NAME pog.zip
      CMAKE_ARGS
         # This does not work on MSVC, but may be useful on Linux.
         -DCMAKE_BUILD_TYPE=Release
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
endif()


check_if_variable_changed(POG_LOCAL_DIR CHANGED)
if(CHANGED)
   ExternalProject_Get_Property(pog-project binary_dir)
   message(STATUS "Pog: path to pog directory changed -> cleaning CMake files in ${binary_dir}.")
   clean_cmake_files(${binary_dir})
endif()

# Set include directories.
ExternalProject_Get_Property(pog-project source_dir)
set(POG_INCLUDE_DIR ${source_dir}/include)

# Add libraries.
ExternalProject_Get_Property(pog-project binary_dir)

if(MSVC)
   set(DEBUG_DIR "Debug/")
   set(RELEASE_DIR "Release/")
endif()

add_library(pog INTERFACE)
target_link_libraries(pog INTERFACE debug ${binary_dir}/src/pog/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}pog${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(pog INTERFACE optimized ${binary_dir}/src/pog/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}pog${CMAKE_STATIC_LIBRARY_SUFFIX})
target_include_directories(pog SYSTEM INTERFACE ${POG_INCLUDE_DIR})
add_dependencies(pog pog-project)
