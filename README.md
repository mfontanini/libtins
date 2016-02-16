# libtins

[![Build status](https://travis-ci.org/mfontanini/libtins.svg?branch=master)](https://travis-ci.org/mfontanini/libtins) 
[![Build status](https://ci.appveyor.com/api/projects/status/33n8ib68nx3tptib/branch/master?svg=true)](https://ci.appveyor.com/project/mfontanini/libtins/branch/master)

libtins is a high-level, multiplatform C++ network packet sniffing and 
crafting library. 

Its main purpose is to provide the C++ developer an easy, efficient, 
platform and endianess-independent way to create tools which need to 
send, receive and manipulate specially crafted packets. 

In order to read tutorials, examples and checkout some benchmarks of the
library, please visit:

http://libtins.github.io/

## Compiling ##

[libtins](http://libtins.github.io/) depends on 
[libpcap](http://www.tcpdump.org/) and 
[openssl](http://www.openssl.org/), although the latter is not necessary 
if some features of the library are disabled.

In order to compile, execute:

```Shell
# Create the build directory
mkdir build
cd build

# Configure the project. Add any relevant configuration flags
cmake ../

# Compile!
make
```

### Static/shared build
Note that by default, only the shared object is compiled. If you would
like to generate a static library file, run:

```Shell
cmake ../ -DLIBTINS_BUILD_SHARED=0
```

The generated static/shared library files will be located in the 
_build/lib_ directory.

### C++11 support

libtins is noticeable faster if you enable _C++11_ support. Therefore, 
if your compiler supports this standard, then you should enable it. 
In order to do so, use the _LIBTINS_ENABLE_CXX11_ switch:

```Shell
cmake ../ -DLIBTINS_ENABLE_CXX11=1
```

### TCP ACK tracker

The TCP ACK tracker feature requires the boost.icl library (header only).
This feature is enabled by default but will be disabled if the boost
headers are not found. You can disable this feature by using:

```Shell
cmake ../ -DLIBTINS_ENABLE_ACK_TRACKER=0
```

If your boost installation is on some non-standard path, use 
the parameters shown on the
[CMake FindBoost help](https://cmake.org/cmake/help/v3.0/module/FindBoost.html)

### WPA2 decryption

If you want to disable _WPA2_ decryption support, which will remove 
openssl as a dependency for compilation, use the 
_LIBTINS_ENABLE_WPA2_ switch:

```Shell
cmake ../ -DLIBTINS_ENABLE_WPA2=0
```

### IEEE 802.11 support

If you want to disable IEEE 802.11 support(this will also disable 
RadioTap and WPA2 decryption), which will reduce the size of the 
resulting library in around 20%, use the _LIBTINS_ENABLE_DOT11_ switch:

```Shell
cmake ../ -DLIBTINS_ENABLE_DOT11=0
```

## Installing ##

Once you're done, if you want to install the header files and the 
shared object, execute as root:

```Shell
make install
```

This will install the shared object typically in _/usr/local/lib_. Note
that you might have to update ldconfig's cache before using it, so 
in order to invalidate it, you should run(as root):

```Shell
ldconfig
```

## Running tests ##

You may want to run the unit tests on your system so you make sure
everything works. In order to do so, you need to follow these steps:

```Shell
# This will fetch the googletest submodule, needed for tests
git submodule init
git submodule update

mkdir build
cd build

# Use any options you want
cmake .. 

# Compile tests
make tests

# Run them
make test
```

If you find that any tests fail, please create an ticket in the
issue tracker indicating the platform and architecture you're using.

## Examples ##

You might want to have a look at the examples located  in the "examples"
directory. The same samples can be found online at:

http://libtins.github.io/examples/

## Contributing ##

If you want to report a bug or make a pull request, please have a look at 
the [contributing](CONTRIBUTING.md) file before doing so.