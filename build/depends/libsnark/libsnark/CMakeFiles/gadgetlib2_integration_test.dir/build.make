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
include depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/flags.make

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.o: depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.o: ../depends/libsnark/libsnark/gadgetlib2/tests/integration_UTEST.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.o"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.o -c /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib2/tests/integration_UTEST.cpp

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.i"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib2/tests/integration_UTEST.cpp > CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.i

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.s"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib2/tests/integration_UTEST.cpp -o CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.s

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.o: depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/flags.make
depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.o: ../depends/libsnark/libsnark/gadgetlib2/examples/simple_example.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.o"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.o -c /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib2/examples/simple_example.cpp

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.i"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib2/examples/simple_example.cpp > CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.i

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.s"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/amirabouguera/SSLES/depends/libsnark/libsnark/gadgetlib2/examples/simple_example.cpp -o CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.s

# Object files for target gadgetlib2_integration_test
gadgetlib2_integration_test_OBJECTS = \
"CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.o" \
"CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.o"

# External object files for target gadgetlib2_integration_test
gadgetlib2_integration_test_EXTERNAL_OBJECTS =

depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/tests/integration_UTEST.cpp.o
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/gadgetlib2/examples/simple_example.cpp.o
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/build.make
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/libsnark/libsnark.a
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/depends/gtest/googlemock/gtest/libgtest_main.a
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/depends/libff/libff/libff.a
depends/libsnark/libsnark/gadgetlib2_integration_test: /usr/local/lib/libgmp.dylib
depends/libsnark/libsnark/gadgetlib2_integration_test: /usr/local/lib/libgmp.dylib
depends/libsnark/libsnark/gadgetlib2_integration_test: /usr/local/lib/libgmpxx.dylib
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/depends/libzm.a
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/depends/gtest/googlemock/gtest/libgtest.a
depends/libsnark/libsnark/gadgetlib2_integration_test: depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/amirabouguera/SSLES/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable gadgetlib2_integration_test"
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gadgetlib2_integration_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/build: depends/libsnark/libsnark/gadgetlib2_integration_test

.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/build

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/clean:
	cd /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/gadgetlib2_integration_test.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/clean

depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/depend:
	cd /Users/amirabouguera/SSLES/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/amirabouguera/SSLES /Users/amirabouguera/SSLES/depends/libsnark/libsnark /Users/amirabouguera/SSLES/build /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark /Users/amirabouguera/SSLES/build/depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/gadgetlib2_integration_test.dir/depend

