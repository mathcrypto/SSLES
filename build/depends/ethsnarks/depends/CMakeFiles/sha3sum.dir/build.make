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
include depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/depend.make

# Include the progress variables for this target.
include depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/progress.make

# Include the compile flags for this target's objects.
include depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/flags.make

depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.o: depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/flags.make
depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.o: ../depends/ethsnarks/depends/SHA3IUF/sha3sum.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.o"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/depends && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.o   -c /Users/amirabouguera/SSLES/depends/ethsnarks/depends/SHA3IUF/sha3sum.c

depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.i"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/depends && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/amirabouguera/SSLES/depends/ethsnarks/depends/SHA3IUF/sha3sum.c > CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.i

depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.s"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/depends && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/amirabouguera/SSLES/depends/ethsnarks/depends/SHA3IUF/sha3sum.c -o CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.s

# Object files for target sha3sum
sha3sum_OBJECTS = \
"CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.o"

# External object files for target sha3sum
sha3sum_EXTERNAL_OBJECTS =

depends/ethsnarks/depends/sha3sum: depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/SHA3IUF/sha3sum.c.o
depends/ethsnarks/depends/sha3sum: depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/build.make
depends/ethsnarks/depends/sha3sum: depends/ethsnarks/depends/libSHA3IUF.a
depends/ethsnarks/depends/sha3sum: depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable sha3sum"
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/depends && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sha3sum.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/build: depends/ethsnarks/depends/sha3sum

.PHONY : depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/build

depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/clean:
	cd /Users/amirabouguera/SSLES/build/depends/ethsnarks/depends && $(CMAKE_COMMAND) -P CMakeFiles/sha3sum.dir/cmake_clean.cmake
.PHONY : depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/clean

depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/depend:
	cd /Users/amirabouguera/SSLES/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES /Users/amirabouguera/SSLES/depends/ethsnarks/depends /Users/amirabouguera/SSLES/build /Users/amirabouguera/SSLES/build/depends/ethsnarks/depends /Users/amirabouguera/SSLES/build/depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/ethsnarks/depends/CMakeFiles/sha3sum.dir/depend

