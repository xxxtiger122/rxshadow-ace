# CMakeLists.txt — 把 lab-ace 全部 C 逻辑编译进 libace.so（App 进程内运行）
cmake_minimum_required(VERSION 3.22.1)
project("ace" C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DACE_AS_LIB -O0 -g")

# lab-ace 源码根（gradle syncAceSources 任务构建时从仓库根同步到 cpp/ace-src）
set(ACE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/ace-src)

add_library(ace SHARED
    ace_jni.c
    ${ACE_ROOT}/labtarget.c
    ${ACE_ROOT}/det_selfcrc.c
    ${ACE_ROOT}/det_elfhash.c
    ${ACE_ROOT}/det_crossread.c
    ${ACE_ROOT}/det_pagemap.c
    ${ACE_ROOT}/det_timing.c
    ${ACE_ROOT}/det_faultcount.c
    ${ACE_ROOT}/det_perf.c
    ${ACE_ROOT}/det_selfmod.c
    ${ACE_ROOT}/det_procscan.c
    ${ACE_ROOT}/det_trampoline.c
    ${ACE_ROOT}/det_callstack.c
    ${ACE_ROOT}/det_hwbp.c
    ${ACE_ROOT}/det_linkmap.c
    ${ACE_ROOT}/det_kallsyms.c
    ${ACE_ROOT}/det_kcore.c
    ${ACE_ROOT}/det_dmesg.c
    ${ACE_ROOT}/det_sysfs.c
    ${ACE_ROOT}/det_diff.c
)

target_include_directories(ace PRIVATE ${ACE_ROOT})
target_link_libraries(ace log)
