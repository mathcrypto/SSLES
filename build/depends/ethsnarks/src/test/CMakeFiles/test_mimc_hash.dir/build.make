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
CMAKE_SOURCE_DIR = /Users/amirabouguera/SSLES

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/amirabouguera/SSLES/build

# Include any dependencies generated for this target.
include depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/depend.make

# Include the progress variables for this target.
include depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/progress.make

# Include the compile flags for this target's objects.
include depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/flags.make

depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.o: depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/flags.make
depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.o: ../depends/ethsnarks/src/test/test_mimc_hash.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.o"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/src/test && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.o -c /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/test_mimc_hash.cpp

depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.i"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/src/test && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/test_mimc_hash.cpp > CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.i

depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.s"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/src/test && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/test_mimc_hash.cpp -o CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.s

# Object files for target test_mimc_hash
test_mimc_hash_OBJECTS = \
"CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.o"

# External object files for target test_mimc_hash
test_mimc_hash_EXTERNAL_OBJECTS =

depends/ethsnarks/src/test/test_mimc_hash: depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/test_mimc_hash.cpp.o
depends/ethsnarks/src/test/test_mimc_hash: depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/build.make
depends/ethsnarks/src/test/test_mimc_hash: depends/ethsnarks/src/gadgets/libethsnarks_gadgets.a
depends/ethsnarks/src/test/test_mimc_hash: depends/ethsnarks/src/libethsnarks_common.a
depends/ethsnarks/src/test/test_mimc_hash: depends/ethsnarks/libff.a
depends/ethsnarks/src/test/test_mimc_hash: /usr/local/lib/libgmp.dylib
depends/ethsnarks/src/test/test_mimc_hash: depends/ethsnarks/depends/libSHA3IUF.a
depends/ethsnarks/src/test/test_mimc_hash: depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_mimc_hash"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/src/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_mimc_hash.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/build: depends/ethsnarks/src/test/test_mimc_hash

.PHONY : depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/build

depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/clean:
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/src/test && $(CMAKE_COMMAND) -P CMakeFiles/test_mimc_hash.dir/cmake_clean.cmake
.PHONY : depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/clean

depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/depend:
	cd /Users/amirabouguera/SSLES/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES /Users/amirabouguera/SSLES/depends/ethsnarks/src/test /Users/amirabouguera/SSLES/build /Users/amirabouguera/SSLES/build/depends/ethsnarks/src/test /Users/amirabouguera/SSLES/build/depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/ethsnarks/src/test/CMakeFiles/test_mimc_hash.dir/depend

