# Contributing

Bug reports and enhancements to the library are really valued and appreciated!

# Bug reports

If you find a bug, please report it! Bugs on the library are taken seriously 
and a patch for them is usually pushed on the same day. 

When reporting a bug, please make sure to indicate the platform (e.g. GNU/Linux, Windows, OSX)
in which you came across the issue, as this is essential to finding the cause.

## Packet parsing bugs

If you find a bug related to packet parsing (e.g. a field on a packet contains an 
invalid value), please try to provide a pcap file that contains the packet that
was incorrectly parsed. Doing this will make it very simple to find the issue, plus
you will be asked to provide this file anyway, so this just makes things
easier.

# Pull requests

Pull requests are very welcomed. When doing a pull request please:

* Base your PR branch on the `develop` branch. This is **almost always** pointing to the
same commit as `master`, so you shouldn't have any issues changing the destination branch
to `develop` at the time you try to do the pull request if you based your code on `master`.
* Your code will be compiled and tests will be run automatically by the travis and 
appveyor CI tools. If your code has issues on any of the tested platforms (GNU/Linux, Windows
and OSX), please fix it or otherwise the PR won't be merged. 
