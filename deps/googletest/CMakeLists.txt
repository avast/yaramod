include(FetchContent)

FetchContent_Declare(
	googletest
	URL https://github.com/google/googletest/archive/a7f443b80b105f940225332ed3c31f2790092f47.zip
	URL_HASH SHA256=ecb351335da20ab23ea5f14c107a10c475dfdd27d8a50d968757942280dffbe3
)

# Without this, googletest's CMakeLists.txt replaces "/MD" (dynamic run-time) with "-MT" (static runtime).
# Default config for most applications is "/MD", so this will cause problems if linked with "-MT" googletest.
# https://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
if(MSVC)
	target_compile_options(gtest PUBLIC "/W3" "/WX-")
	target_compile_options(gmock PUBLIC "/W3" "/WX-")
	target_compile_options(gtest_main PUBLIC "/W3" "/WX-")
	target_compile_options(gmock_main PUBLIC "/W3" "/WX-")
endif()
