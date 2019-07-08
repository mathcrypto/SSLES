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
include ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/depend.make

# Include the progress variables for this target.
include ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/progress.make

# Include the compile flags for this target's objects.
include ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/flags.make

ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.o: ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/flags.make
ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.o: /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/jubjub/test_jubjub_commitment.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/.build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.o"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/jubjub && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.o -c /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/jubjub/test_jubjub_commitment.cpp

ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.i"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/jubjub && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/jubjub/test_jubjub_commitment.cpp > CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.i

ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.s"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/jubjub && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/jubjub/test_jubjub_commitment.cpp -o CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.s

# Object files for target test_jubjub_commitment
test_jubjub_commitment_OBJECTS = \
"CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.o"

# External object files for target test_jubjub_commitment
test_jubjub_commitment_EXTERNAL_OBJECTS =

ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/test_jubjub_commitment.cpp.o
ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/build.make
ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/src/jubjub/libethsnarks_jubjub.a
ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/src/gadgets/libethsnarks_gadgets.a
ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/src/libethsnarks_common.a
ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/libff.a
ethsnarks/src/test/jubjub/test_jubjub_commitment: /usr/local/lib/libgmp.dylib
ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/depends/libSHA3IUF.a
ethsnarks/src/test/jubjub/test_jubjub_commitment: ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/amirabouguera/SSLES/.build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_jubjub_commitment"
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/jubjub && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_jubjub_commitment.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/build: ethsnarks/src/test/jubjub/test_jubjub_commitment

.PHONY : ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/build

ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/clean:
	cd /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/jubjub && $(CMAKE_COMMAND) -P CMakeFiles/test_jubjub_commitment.dir/cmake_clean.cmake
.PHONY : ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/clean

ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/depend:
	cd /Users/amirabouguera/SSLES/.build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES/src /Users/amirabouguera/SSLES/depends/ethsnarks/src/test/jubjub /Users/amirabouguera/SSLES/.build /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/jubjub /Users/amirabouguera/SSLES/.build/ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : ethsnarks/src/test/jubjub/CMakeFiles/test_jubjub_commitment.dir/depend

