# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.14

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.14.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.14.3/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/amirabouguera/SSLES/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/amirabouguera/SSLES/.build

# Utility rule file for ExperimentalStart.

# Include the progress variables for this target.
include ethsnarks/CMakeFiles/ExperimentalStart.dir/progress.make

ethsnarks/CMakeFiles/ExperimentalStart:
	cd /Users/amirabouguera/SSLES/.build/ethsnarks && /usr/local/Cellar/cmake/3.14.3/bin/ctest -D ExperimentalStart

ExperimentalStart: ethsnarks/CMakeFiles/ExperimentalStart
ExperimentalStart: ethsnarks/CMakeFiles/ExperimentalStart.dir/build.make

.PHONY : ExperimentalStart

# Rule to build all files generated by this target.
ethsnarks/CMakeFiles/ExperimentalStart.dir/build: ExperimentalStart

.PHONY : ethsnarks/CMakeFiles/ExperimentalStart.dir/build

ethsnarks/CMakeFiles/ExperimentalStart.dir/clean:
	cd /Users/amirabouguera/SSLES/.build/ethsnarks && $(CMAKE_COMMAND) -P CMakeFiles/ExperimentalStart.dir/cmake_clean.cmake
.PHONY : ethsnarks/CMakeFiles/ExperimentalStart.dir/clean

ethsnarks/CMakeFiles/ExperimentalStart.dir/depend:
	cd /Users/amirabouguera/SSLES/.build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES/src /Users/amirabouguera/SSLES/depends/ethsnarks /Users/amirabouguera/SSLES/.build /Users/amirabouguera/SSLES/.build/ethsnarks /Users/amirabouguera/SSLES/.build/ethsnarks/CMakeFiles/ExperimentalStart.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : ethsnarks/CMakeFiles/ExperimentalStart.dir/depend

