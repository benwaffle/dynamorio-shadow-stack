cmake_minimum_required(VERSION 3.0)
project(dynamorio_shadow_stack)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -g -O3")
set(DynamoRIO_DIR "${CMAKE_SOURCE_DIR}/dynamorio/exports/cmake")
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif()

add_library(shadowstack SHARED shadowstack.c)

configure_DynamoRIO_client(shadowstack)
use_DynamoRIO_extension(shadowstack drmgr)
use_DynamoRIO_extension(shadowstack drsyms)
use_DynamoRIO_extension(shadowstack drwrap)
use_DynamoRIO_extension(shadowstack drcontainers)
