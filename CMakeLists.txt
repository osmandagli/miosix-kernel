# Copyright (C) 2024 by Skyward
#
# This program is free software; you can redistribute it and/or
# it under the terms of the GNU General Public License as published
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# As a special exception, if other files instantiate templates or use
# macros or inline functions from this file, or you compile this file
# and link it with other works to produce a work based on this file,
# this file does not by itself cause the resulting work to be covered
# by the GNU General Public License. However the source code for this
# file must still be made available in accordance with the GNU
# Public License. This exception does not invalidate any other
# why a work based on this file might be covered by the GNU General
# Public License.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>

cmake_minimum_required(VERSION 3.16)

# Make sure the miosix cmake modules are always findable, regardless of
# whether the toolchain file has already populated CMAKE_MODULE_PATH in cache.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/miosix/cmake")

project(Main C CXX ASM)

# Set here your board of choice
set(MIOSIX_OPT_BOARD NOT_SET CACHE STRING "stm32f407vg_stm32f4discovery")

add_subdirectory(miosix EXCLUDE_FROM_ALL)
include(LinkTarget)

# List here your source files (.s, .c and .cpp)
add_executable(main main.cpp)
miosix_link_target(main PUBLIC)

# List here additional include directories
# target_include_directories(main PRIVATE here_your_includes)

# List here additional static libraries
# target_link_libraries(main PRIVATE here_your_libraries)

# To enable ASPIS set MIOSIX_ENABLE_ASPIS=ON
option(MIOSIX_ENABLE_ASPIS "Build an ASPIS-hardened variant of the main target" OFF)
# Choose the hardening passes to apply
set(MIOSIX_ASPIS_DUP "eddi"  CACHE STRING "ASPIS data-protection pass (eddi|reddi|seddi|fdsc|no-dup)")
set(MIOSIX_ASPIS_CFC "cfcss" CACHE STRING "ASPIS control-flow-checking pass (cfcss|rasm|inter-rasm|no-cfc)")

if(MIOSIX_ENABLE_ASPIS)
    include(ASPIS)
    miosix_aspis_target(main "--${MIOSIX_ASPIS_DUP}" "--${MIOSIX_ASPIS_CFC}")
endif()
