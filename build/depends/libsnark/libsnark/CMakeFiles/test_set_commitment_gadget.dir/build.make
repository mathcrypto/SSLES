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
include depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.o: depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.o: ../depends/libsnark/libsnark/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.o"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.o -c /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp

depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.i"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp > CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.i

depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.s"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp -o CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.s

# Object files for target test_set_commitment_gadget
test_set_commitment_gadget_OBJECTS = \
"CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.o"

# External object files for target test_set_commitment_gadget
test_set_commitment_gadget_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/test_set_commitment_gadget: depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/gadgetlib1/gadgets/set_commitment/tests/test_set_commitment_gadget.cpp.o
depends/libsnark/libsnark/test_set_commitment_gadget: depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/build.make
depends/libsnark/libsnark/test_set_commitment_gadget: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/test_set_commitment_gadget: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/test_set_commitment_gadget: /usr/local/lib/libgmp.dylib
depends/libsnark/libsnark/test_set_commitment_gadget: /usr/local/lib/libgmp.dylib
depends/libsnark/libsnark/test_set_commitment_gadget: /usr/local/lib/libgmpxx.dylib
depends/libsnark/libsnark/test_set_commitment_gadget: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/test_set_commitment_gadget: depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_set_commitment_gadget"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_set_commitment_gadget.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/build: depends/libsnark/libsnark/test_set_commitment_gadget

.PHONY : depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/build

depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/clean:
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/test_set_commitment_gadget.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/clean

depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/depend:
	cd /Users/amirabouguera/SSLES/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES /Users/amirabouguera/SSLES/depends/libsnark/libsnark /Users/amirabouguera/SSLES/build /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/test_set_commitment_gadget.dir/depend

