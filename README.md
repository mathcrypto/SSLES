# SSLES
Single Secret Leader Election Snark



Build instructions

Fetch dependencies from their GitHub repos:

```$ git submodule init && git submodule update```

Create the Makefile:

```$ mkdir build && cd build

   $LD_LIBRARY_PATH=/usr/local/opt/openssl/lib:"${LD_LIBRARY_PATH}"                  
   CPATH=/usr/local/opt/openssl/include:"${CPATH}"                                   
   PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:"${PKG_CONFIG_PATH}"        
   export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH  
   CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib
   PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig cmake -DWITH_PROCPS=OFF -DWITH_SUPERCOP=OFF ..```


Then, to compile the library, tests, and profiling harness, run this within the build directory:

```$ make```

