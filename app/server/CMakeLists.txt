AUX_SOURCE_DIRECTORY(. SRC_LIST)
ADD_EXECUTABLE(server ${SRC_LIST})
target_link_libraries(server -lrt)
