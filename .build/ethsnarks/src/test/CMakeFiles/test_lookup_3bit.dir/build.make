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
include ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/depend.make

# Include the progress variables for this target.
include ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/progress.make

# Include the compile flags for this target's objects.
include ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/flags.make

ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.o: ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/flags.make
ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.o: /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/test_lookup_3bit.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/.build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.o"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.o -c /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/test_lookup_3bit.cpp

ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.i"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/test_lookup_3bit.cpp > CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.i

ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.s"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/test_lookup_3bit.cpp -o CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.s

# Object files for target test_lookup_3bit
test_lookup_3bit_OBJECTS = \
"CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.o"

# External object files for target test_lookup_3bit
test_lookup_3bit_EXTERNAL_OBJECTS =

ethsnarks/src/test/test_lookup_3bit: ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/test_lookup_3bit.cpp.o
ethsnarks/src/test/test_lookup_3bit: ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/build.make
ethsnarks/src/test/test_lookup_3bit: ethsnarks/src/gadgets/libethsnarks_gadgets.a
ethsnarks/src/test/test_lookup_3bit: ethsnarks/src/libethsnarks_common.a
ethsnarks/src/test/test_lookup_3bit: ethsnarks/libff.a
ethsnarks/src/test/test_lookup_3bit: /usr/local/lib/libgmp.dylib
ethsnarks/src/test/test_lookup_3bit: ethsnarks/depends/libSHA3IUF.a
ethsnarks/src/test/test_lookup_3bit: ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/amirabouguera/SSLES/.build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_lookup_3bit"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_lookup_3bit.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/build: ethsnarks/src/test/test_lookup_3bit

.PHONY : ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/build

ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/clean:
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test && $(CMAKE_COMMAND) -P CMakeFiles/test_lookup_3bit.dir/cmake_clean.cmake
.PHONY : ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/clean

ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/depend:
	cd /Users/amirabouguera/SSLES/.build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES/src /Users/amirabouguera/SSLES/depends/ethsnarks/src/test /Users/amirabouguera/SSLES/.build /Users/amirabouguera/SSLES/.build/ethsnarks/src/test /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : ethsnarks/src/test/CMakeFiles/test_lookup_3bit.dir/depend

