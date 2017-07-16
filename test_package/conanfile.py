from conans import ConanFile, CMake
import os


class LibtinsTestConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    channel = os.getenv("CONAN_CHANNEL", "testing")
<<<<<<< HEAD
    username = os.getenv("CONAN_USERNAME", "appanywhere")
=======
    username = os.getenv("CONAN_USERNAME", "mfontanini")
>>>>>>> develop
    requires = "libtins/3.5@%s/%s" % (username, channel)
    generators = "cmake"

    def build(self):
        cmake = CMake(self)
        cmake.configure(build_dir="./")
        cmake.build()

    def imports(self):
<<<<<<< HEAD
=======
        self.copy("*.so*", dst="bin", src="bin")
>>>>>>> develop
        self.copy("*.dll", dst="bin", src="bin")
        self.copy("*.dylib*", dst="bin", src="lib")

    def test(self):
        cmake = CMake(self)
        cmake.configure(build_dir="./")
        cmake.test()
