# Finder for C++ filesystem library.
#
# Ensures that stdc++fs or c++fs is used when needed
# by the compiler.


if(NOT TARGET Filesystem::Filesystem)
	add_library(Filesystem::Filesystem INTERFACE IMPORTED)

	# Clang
	if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
		# Clang older than 9.x needs -lc++fs
		if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
			set_target_properties(Filesystem::Filesystem PROPERTIES INTERFACE_LINK_LIBRARIES c++fs)
		endif()
	# GCC
	elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		# GCC older than 9.x needs -lstdc++fs
		if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
			set_target_properties(Filesystem::Filesystem PROPERTIES INTERFACE_LINK_LIBRARIES stdc++fs)
		endif()
	endif()
endif()
