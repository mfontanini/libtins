libtins
=======

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

Note that by default, only the shared object is compiled. If you would
like to generate a static library file, run:

```Shell
cmake ../ -DLIBTINS_BUILD_SHARED=0
```

The generated static/shared library files will be located in the 
_build/lib_ directory.

libtins is noticeable faster if you enable _C++11_ support. Therefore, 
if your compiler supports this standard, then you should enable it. 
In order to do so, use the _LIBTINS_ENABLE_CXX11_ switch:

```Shell
cmake ../ -DLIBTINS_ENABLE_CXX11=1
```

If you want to disable _WPA2_ decryption support, which will remove 
openssl as a dependency for compilation, use the 
_LIBTINS_ENABLE_WPA2_ switch:

```Shell
cmake ../ -DLIBTINS_ENABLE_WPA2=0
```

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

## Examples ##

You might want to have a look at the examples located  in the "examples"
directory. The same samples can be found online at:

http://libtins.github.io/examples/
