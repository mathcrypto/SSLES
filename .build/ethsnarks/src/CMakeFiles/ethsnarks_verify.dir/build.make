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

# Include any dependencies generated for this target.
include ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/depend.make

# Include the progress variables for this target.
include ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/progress.make

# Include the compile flags for this target's objects.
include ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/flags.make

ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.o: ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/flags.make
ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.o: /Users/amirabouguera/SSLES/depends/ethsnarks/src/verify_dll.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/.build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.o"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.o -c /Users/amirabouguera/SSLES/depends/ethsnarks/src/verify_dll.cpp

ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.i"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/amirabouguera/SSLES/depends/ethsnarks/src/verify_dll.cpp > CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.i

ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.s"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/amirabouguera/SSLES/depends/ethsnarks/src/verify_dll.cpp -o CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.s

# Object files for target ethsnarks_verify
ethsnarks_verify_OBJECTS = \
"CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.o"

# External object files for target ethsnarks_verify
ethsnarks_verify_EXTERNAL_OBJECTS =

ethsnarks/src/libethsnarks_verify.dylib: ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/verify_dll.cpp.o
ethsnarks/src/libethsnarks_verify.dylib: ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/build.make
ethsnarks/src/libethsnarks_verify.dylib: ethsnarks/src/libethsnarks_common.a
ethsnarks/src/libethsnarks_verify.dylib: ethsnarks/libff.a
ethsnarks/src/libethsnarks_verify.dylib: /usr/local/lib/libgmp.dylib
ethsnarks/src/libethsnarks_verify.dylib: ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/amirabouguera/SSLES/.build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared library libethsnarks_verify.dylib"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ethsnarks_verify.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/build: ethsnarks/src/libethsnarks_verify.dylib

.PHONY : ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/build

ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/clean:
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src && $(CMAKE_COMMAND) -P CMakeFiles/ethsnarks_verify.dir/cmake_clean.cmake
.PHONY : ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/clean

ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/depend:
	cd /Users/amirabouguera/SSLES/.build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES/src /Users/amirabouguera/SSLES/depends/ethsnarks/src /Users/amirabouguera/SSLES/.build /Users/amirabouguera/SSLES/.build/ethsnarks/src /Users/amirabouguera/SSLES/.build/ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : ethsnarks/src/CMakeFiles/ethsnarks_verify.dir/depend
