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

# ASPIS integration for Miosix
#
# Provides miosix_aspis_target(<target> [--seddi|--fdsc|--no-dup]
#                                       [--cfcss|--rasm|--inter-rasm|--no-cfc])
#
# Creates a new CMake target named <target>_aspis along <target> that compiles the same
# C/C++ sources as <target> through the ASPIS LLVM IR hardening pipeline and links
# them against the miosix kernel libraries.
#
# Prerequisites:
#   - Clang toolchain (clang.cmake) must be active
#   - ASPIS must be built: cd /path/to/ASPIS && cmake -B build && cmake --build build
#   - DataCorruption_Handler() and SigMismatch_Handler() must be defined in
#     one of the compiled source files (extern "C" linkage in C++ code)


# Point this at your local ASPIS checkout; override it if the repo lives elsewhere.
set(ASPIS_DIR "/WORKSPACE/ASPIS" CACHE PATH "Path to the ASPIS repository root")

# miosix_aspis_target(<target> [options])
#
# Data protection options (mutually exclusive, default: --eddi):
#   --eddi       Full instruction duplication + checks at stores/calls/branches
#   --reddi      Like EDDI but without DUPLICATE_ALL (selective instruction dup)
#   --seddi      Selective-EDDI: checks only at calls and branches
#   --fdsc       Full Duplication with Selective Checking: checks at merge points
#   --no-dup     Disable data duplication entirely
#
# Control-flow checking options (mutually exclusive, default: --cfcss):
#   --cfcss      Intra-function CFC via static block signatures
#   --rasm       Intra-function CFC via random additive signatures
#   --inter-rasm Inter-function CFC via random additive signatures
#   --racfed     RACFED control-flow error detection
#   --no-cfc     Disable control-flow checking entirely
function(miosix_aspis_target TARGET)

    # -------------------------------------------------------------------------
    # Parse optional arguments
    # -------------------------------------------------------------------------
    set(ASPIS_DUP  "eddi")
    set(ASPIS_CFC  "cfcss")

    # Keep the interface small: only the supported ASPIS switches are accepted here.
    foreach(OPT ${ARGN})
        if(OPT STREQUAL "--eddi")
            set(ASPIS_DUP "eddi")
        elseif(OPT STREQUAL "--reddi")
            set(ASPIS_DUP "reddi")
        elseif(OPT STREQUAL "--seddi")
            set(ASPIS_DUP "seddi")
        elseif(OPT STREQUAL "--fdsc")
            set(ASPIS_DUP "fdsc")
        elseif(OPT STREQUAL "--no-dup")
            set(ASPIS_DUP "none")
        elseif(OPT STREQUAL "--cfcss")
            set(ASPIS_CFC "cfcss")
        elseif(OPT STREQUAL "--rasm")
            set(ASPIS_CFC "rasm")
        elseif(OPT STREQUAL "--inter-rasm")
            set(ASPIS_CFC "inter_rasm")
        elseif(OPT STREQUAL "--racfed")
            set(ASPIS_CFC "racfed")
        elseif(OPT STREQUAL "--no-cfc")
            set(ASPIS_CFC "none")
        else()
            message(WARNING "miosix_aspis_target: Unknown option '${OPT}' ignored")
        endif()
    endforeach()

    # -------------------------------------------------------------------------
    # Validate prerequisites
    # -------------------------------------------------------------------------

    # Check that the active compiler is Clang, since ASPIS relies on Clang-specific
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "miosix_aspis_target requires the Clang toolchain (clang.cmake)")
    endif()

    # Check that the ASPIS passes .so files are present (i.e. ASPIS has been built)
    set(ASPIS_PASSES_DIR "${ASPIS_DIR}/build/passes")
    if(NOT EXISTS "${ASPIS_PASSES_DIR}/libEDDI.so")
        message(FATAL_ERROR
            "ASPIS passes not found at ${ASPIS_PASSES_DIR}.\n"
            "Build ASPIS first:\n"
            "  cd ${ASPIS_DIR} && cmake -B build -DLLVM_DIR=${LLVM_PREFIX}/../lib/cmake/llvm && cmake --build build"
        )
    endif()

    # Check that the miosix target exists
    if(NOT TARGET miosix)
        message(FATAL_ERROR "miosix_aspis_target: 'miosix' target not found. Add miosix subdirectory first.")
    endif()

    # -------------------------------------------------------------------------
    # Tool paths — all from the same LLVM 21 build (CMAKE_C_COMPILER is
    # /WORKSPACE/llvm-21/build/bin/clang, which has the ARM backend).
    # -------------------------------------------------------------------------
    set(ASPIS_CLANG   "${CMAKE_C_COMPILER}")
    set(ASPIS_CLANGPP "${CMAKE_CXX_COMPILER}")
    set(ASPIS_LINK    "${LLVM_PREFIX}/llvm-link")
    set(ASPIS_OPT     "${LLVM_PREFIX}/opt")

    # -------------------------------------------------------------------------
    # Collect compilation flags from the miosix target
    #
    # TARGET_CXX_FLAGS is a custom property set by miosix/CMakeLists.txt:
    #   set_property(TARGET miosix PROPERTY TARGET_CXX_FLAGS
    #                ${MIOSIX_CXX_FLAGS} ${MIOSIX_L_FLAGS})
    #
    # Additionally, the Clang toolchain file (clang.cmake) adds global
    # definitions via add_compile_definitions() using generator expressions
    # like $<$<COMPILE_LANGUAGE:C,CXX>:_MIOSIX>. These are NOT captured in
    # TARGET_CXX_FLAGS, so we retrieve them separately from the directory
    # COMPILE_DEFINITIONS property and strip the generator expression wrappers.
    #
    # For IR emission we need:  arch flags + defines   (no -c, no -Wl/linker flags)
    # For IR → object we need:  arch flags only        (no defines, no -c)
    # -------------------------------------------------------------------------
    get_target_property(MIOSIX_ALL_FLAGS miosix TARGET_CXX_FLAGS)
    if(NOT MIOSIX_ALL_FLAGS)
        message(FATAL_ERROR
            "miosix target is missing TARGET_CXX_FLAGS property.\n"
            "Make sure to set it in miosix/CMakeLists.txt:\n")
    endif()

    # Grab the toolchain-level defines too; they do not show up in TARGET_CXX_FLAGS.
    get_directory_property(DIR_COMPILE_DEFS COMPILE_DEFINITIONS)
    set(DIR_DEF_FLAGS)
    foreach(DEF ${DIR_COMPILE_DEFS})
        if(DEF MATCHES "^\\$<\\$<COMPILE_LANGUAGE:[^>]+>:([^>]+)>$")
            # Generator expression: $<$<COMPILE_LANGUAGE:C,CXX>:FOO> → -DFOO
            list(APPEND DIR_DEF_FLAGS "-D${CMAKE_MATCH_1}")
        elseif(NOT DEF MATCHES "^\\$<")
            # Plain definition (no genex): FOO → -DFOO
            list(APPEND DIR_DEF_FLAGS "-D${DEF}")
        endif()
    endforeach()

    # Flags for the clang frontend (IR emission)
    set(IR_FLAGS ${MIOSIX_ALL_FLAGS} ${DIR_DEF_FLAGS})
    list(REMOVE_ITEM IR_FLAGS "-c")                            # conflicts with -S -emit-llvm
    list(FILTER IR_FLAGS EXCLUDE REGEX "^-Wl,")                # linker pass-through flags
    list(FILTER IR_FLAGS EXCLUDE REGEX "^-nostdlib$")          # linker flag
    list(REMOVE_DUPLICATES IR_FLAGS)

    # Architecture-only flags for clang backend (IR → object)
    set(ARCH_FLAGS)
    foreach(FLAG ${IR_FLAGS})
        if(FLAG MATCHES "^-m(cpu|arch|thumb|float|fpu|arm|eabi|abi|tune)|^-mthumb$")
            list(APPEND ARCH_FLAGS "${FLAG}")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES ARCH_FLAGS)

    # Include directories from miosix's public interface
    get_target_property(MIOSIX_INC_DIRS miosix INTERFACE_INCLUDE_DIRECTORIES)
    set(INC_FLAGS)
    foreach(INC ${MIOSIX_INC_DIRS})
        list(APPEND INC_FLAGS "-I${INC}")
    endforeach()

    # -------------------------------------------------------------------------
    # Source files
    # -------------------------------------------------------------------------
    get_target_property(TARGET_SOURCES ${TARGET} SOURCES)
    if(NOT TARGET_SOURCES)
        message(FATAL_ERROR "miosix_aspis_target: target '${TARGET}' has no sources")
    endif()

    set(ASPIS_BUILD "${CMAKE_CURRENT_BINARY_DIR}/aspis_${TARGET}")

    # -------------------------------------------------------------------------
    # Step 1 — Emit LLVM IR for each C/C++ source file
    # -------------------------------------------------------------------------
    set(LL_FILES)
    foreach(SRC ${TARGET_SOURCES})
        if(NOT IS_ABSOLUTE "${SRC}")
            set(SRC "${CMAKE_CURRENT_SOURCE_DIR}/${SRC}")
        endif()

        get_filename_component(SRC_EXT  "${SRC}" EXT)
        get_filename_component(SRC_STEM "${SRC}" NAME_WE)

        if(SRC_EXT MATCHES "\\.(cpp|cxx|cc|C)$")
            set(FE "${ASPIS_CLANGPP}")
        elseif(SRC_EXT MATCHES "\\.c$")
            set(FE "${ASPIS_CLANG}")
        else()
            # Skip assembly and other non-C/C++ files
            continue()  
        endif()

        set(LL_OUT "${ASPIS_BUILD}/${SRC_STEM}.ll")

        add_custom_command(
            OUTPUT  "${LL_OUT}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${ASPIS_BUILD}"
            COMMAND "${FE}"
                    --target=arm-none-eabi
                    ${IR_FLAGS}
                    ${INC_FLAGS}
                    -S -emit-llvm -O0
                    -Xclang -disable-O0-optnone
                    "${SRC}"
                    -o "${LL_OUT}"
            DEPENDS "${SRC}"
            COMMENT "ASPIS[${TARGET}]: Emitting IR — ${SRC_STEM}"
            VERBATIM
        )
        list(APPEND LL_FILES "${LL_OUT}")
    endforeach()

    if(NOT LL_FILES)
        message(FATAL_ERROR "miosix_aspis_target: No C/C++ source files found in target '${TARGET}'")
    endif()

    # -------------------------------------------------------------------------
    # Step 2 — Link all IR modules into a single file
    # -------------------------------------------------------------------------
    set(LINKED_LL "${ASPIS_BUILD}/out.ll")
    add_custom_command(
        OUTPUT  "${LINKED_LL}"
        COMMAND "${ASPIS_LINK}"
                ${LL_FILES}
                -o "${LINKED_LL}"
                -S
        DEPENDS ${LL_FILES}
        COMMENT "ASPIS[${TARGET}]: Linking IR modules"
        VERBATIM
    )

    # -------------------------------------------------------------------------
    # Step 3 — Preprocessing: strip debug info, then lower switch statements
    #
    # ASPIS inserts new call instructions (e.g. DataCorruption_Handler) without
    # debug location metadata. LLVM's verifier requires every call in a function
    # with debug info to carry a !dbg location, so we strip debug info before
    # applying the ASPIS passes (matching aspis.sh's default behaviour).
    # -------------------------------------------------------------------------
    set(STRIPPED_LL "${ASPIS_BUILD}/stripped.ll")
    add_custom_command(
        OUTPUT  "${STRIPPED_LL}"
        COMMAND "${ASPIS_OPT}"
                --passes=strip -S
                "${LINKED_LL}" -o "${STRIPPED_LL}"
        DEPENDS "${LINKED_LL}"
        COMMENT "ASPIS[${TARGET}]: Stripping debug info"
        VERBATIM
    )

    set(LOWERED_LL "${ASPIS_BUILD}/lowered.ll")
    add_custom_command(
        OUTPUT  "${LOWERED_LL}"
        COMMAND "${ASPIS_OPT}"
                --passes=lower-switch -S
                "${STRIPPED_LL}" -o "${LOWERED_LL}"
        DEPENDS "${STRIPPED_LL}"
        COMMENT "ASPIS[${TARGET}]: Lowering switch statements"
        VERBATIM
    )

    # -------------------------------------------------------------------------
    # Step 4 — Data protection passes
    # -------------------------------------------------------------------------

    # 4a. FuncRetToRef: transform return-value functions → void + reference param
    set(FUNCRET_LL "${ASPIS_BUILD}/funcret.ll")
    if(NOT ASPIS_DUP STREQUAL "none")
        add_custom_command(
            OUTPUT  "${FUNCRET_LL}"
            COMMAND "${ASPIS_OPT}"
                    -load-pass-plugin=${ASPIS_PASSES_DIR}/libEDDI.so
                    --passes=func-ret-to-ref -S
                    "${LOWERED_LL}" -o "${FUNCRET_LL}"
            DEPENDS "${LOWERED_LL}"
            COMMENT "ASPIS[${TARGET}]: FuncRetToRef"
            VERBATIM
        )
    else()
        # No duplication: skip FuncRetToRef, just copy
        add_custom_command(
            OUTPUT  "${FUNCRET_LL}"
            COMMAND ${CMAKE_COMMAND} -E copy "${LOWERED_LL}" "${FUNCRET_LL}"
            DEPENDS "${LOWERED_LL}"
            COMMENT "ASPIS[${TARGET}]: Skipping FuncRetToRef (--no-dup)"
            VERBATIM
        )
    endif()

    # 4b. Data duplication pass (EDDI / sEDDI / FDSC)
    set(DUP_LL "${ASPIS_BUILD}/dup.ll")
    if(ASPIS_DUP STREQUAL "eddi")
        set(DUP_LIB "${ASPIS_PASSES_DIR}/libEDDI.so")
    elseif(ASPIS_DUP STREQUAL "reddi")
        set(DUP_LIB "${ASPIS_PASSES_DIR}/libREDDI.so")
    elseif(ASPIS_DUP STREQUAL "seddi")
        set(DUP_LIB "${ASPIS_PASSES_DIR}/libSEDDI.so")
    elseif(ASPIS_DUP STREQUAL "fdsc")
        set(DUP_LIB "${ASPIS_PASSES_DIR}/libFDSC.so")
    endif()

    if(NOT ASPIS_DUP STREQUAL "none")
        add_custom_command(
            OUTPUT  "${DUP_LL}"
            COMMAND "${ASPIS_OPT}"
                    -load-pass-plugin=${DUP_LIB}
                    --passes=eddi-verify -S
                    "${FUNCRET_LL}" -o "${DUP_LL}"
            DEPENDS "${FUNCRET_LL}"
            COMMENT "ASPIS[${TARGET}]: ${ASPIS_DUP} data protection"
            VERBATIM
        )
    else()
        add_custom_command(
            OUTPUT  "${DUP_LL}"
            COMMAND ${CMAKE_COMMAND} -E copy "${FUNCRET_LL}" "${DUP_LL}"
            DEPENDS "${FUNCRET_LL}"
            COMMENT "ASPIS[${TARGET}]: Skipping data duplication (--no-dup)"
            VERBATIM
        )
    endif()

    # -------------------------------------------------------------------------
    # Step 5 — SimplifyCFG (clean up IR after duplication)
    # -------------------------------------------------------------------------
    set(SIMPLIFIED_LL "${ASPIS_BUILD}/simplified.ll")
    add_custom_command(
        OUTPUT  "${SIMPLIFIED_LL}"
        COMMAND "${ASPIS_OPT}"
                --passes=simplifycfg -S
                "${DUP_LL}" -o "${SIMPLIFIED_LL}"
        DEPENDS "${DUP_LL}"
        COMMENT "ASPIS[${TARGET}]: SimplifyCFG"
        VERBATIM
    )

    # -------------------------------------------------------------------------
    # Step 6 — Control-flow checking pass (CFCSS / RASM / inter-RASM)
    # -------------------------------------------------------------------------
    set(CFC_LL "${ASPIS_BUILD}/cfc.ll")
    if(ASPIS_CFC STREQUAL "cfcss")
        set(CFC_LIB  "${ASPIS_PASSES_DIR}/libCFCSS.so")
        set(CFC_PASS "cfcss-verify")
    elseif(ASPIS_CFC STREQUAL "rasm")
        set(CFC_LIB  "${ASPIS_PASSES_DIR}/libRASM.so")
        set(CFC_PASS "rasm-verify")
    elseif(ASPIS_CFC STREQUAL "inter_rasm")
        set(CFC_LIB  "${ASPIS_PASSES_DIR}/libINTER_RASM.so")
        set(CFC_PASS "rasm-verify")
    elseif(ASPIS_CFC STREQUAL "racfed")
        set(CFC_LIB  "${ASPIS_PASSES_DIR}/libRACFED.so")
        set(CFC_PASS "racfed-verify")
    endif()

    if(NOT ASPIS_CFC STREQUAL "none")
        add_custom_command(
            OUTPUT  "${CFC_LL}"
            COMMAND "${ASPIS_OPT}"
                    -load-pass-plugin=${CFC_LIB}
                    --passes=${CFC_PASS} -S
                    "${SIMPLIFIED_LL}" -o "${CFC_LL}"
            DEPENDS "${SIMPLIFIED_LL}"
            COMMENT "ASPIS[${TARGET}]: ${ASPIS_CFC} control-flow checking"
            VERBATIM
        )
    else()
        add_custom_command(
            OUTPUT  "${CFC_LL}"
            COMMAND ${CMAKE_COMMAND} -E copy "${SIMPLIFIED_LL}" "${CFC_LL}"
            DEPENDS "${SIMPLIFIED_LL}"
            COMMENT "ASPIS[${TARGET}]: Skipping control-flow checking (--no-cfc)"
            VERBATIM
        )
    endif()

    # -------------------------------------------------------------------------
    # Step 7 — Duplicate globals (finalise global variable duplication)
    # -------------------------------------------------------------------------
    set(FINAL_LL "${ASPIS_BUILD}/aspis_final.ll")
    if(NOT ASPIS_DUP STREQUAL "none")
        add_custom_command(
            OUTPUT  "${FINAL_LL}"
            COMMAND "${ASPIS_OPT}"
                    -load-pass-plugin=${ASPIS_PASSES_DIR}/libEDDI.so
                    --passes=duplicate-globals -S
                    "${CFC_LL}" -o "${FINAL_LL}"
            DEPENDS "${CFC_LL}"
            COMMENT "ASPIS[${TARGET}]: Duplicating globals"
            VERBATIM
        )
    else()
        add_custom_command(
            OUTPUT  "${FINAL_LL}"
            COMMAND ${CMAKE_COMMAND} -E copy "${CFC_LL}" "${FINAL_LL}"
            DEPENDS "${CFC_LL}"
            COMMENT "ASPIS[${TARGET}]: Skipping global duplication (--no-dup)"
            VERBATIM
        )
    endif()

    # -------------------------------------------------------------------------
    # Step 8 — Compile hardened IR back to an ARM Cortex-M object file
    # -------------------------------------------------------------------------
    set(ASPIS_OBJ "${ASPIS_BUILD}/aspis_out.o")
    add_custom_command(
        OUTPUT  "${ASPIS_OBJ}"
        COMMAND "${ASPIS_CLANGPP}"
                --target=arm-none-eabi
                ${ARCH_FLAGS}
                -c "${FINAL_LL}"
                -o "${ASPIS_OBJ}"
        DEPENDS "${FINAL_LL}"
        COMMENT "ASPIS[${TARGET}]: Compiling hardened IR to ARM object"
        VERBATIM
    )

    # -------------------------------------------------------------------------
    # Step 9 — Create the hardened executable and link against miosix
    # -------------------------------------------------------------------------
    set_source_files_properties("${ASPIS_OBJ}" PROPERTIES
        GENERATED       TRUE
        EXTERNAL_OBJECT TRUE
    )
    # Tell CMake this object is produced by the pipeline, not by a normal compile step.
    add_executable(${TARGET}_aspis "${ASPIS_OBJ}")
    set_target_properties(${TARGET}_aspis PROPERTIES LINKER_LANGUAGE CXX)
    miosix_link_target(${TARGET}_aspis PUBLIC)

    message(STATUS "ASPIS target '${TARGET}_aspis' configured (dup=${ASPIS_DUP}, cfc=${ASPIS_CFC})")

endfunction()
