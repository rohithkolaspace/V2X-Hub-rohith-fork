cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(pedestrian_plugin_server_api_lib)

include_directories(${EXTERNAL_INSTALL_LOCATION}/include)
link_directories(${EXTERNAL_INSTALL_LOCATION}/lib)

add_subdirectory(src)
