include(GNUInstallDirs)

install(
    FILES json.hpp
    DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/yaramod/json/
)
