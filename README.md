# FiberFS

FiberFS is a fully featured POSIX filesystem that uses S3 compatible storage as a backend.

For more informations, please visit [FiberFS.io](https://fiberfs.io/).

## Building

```
make
```

Note: all Makefile commands support parallism, ex: `make -j4`.

## Testing and Safety

```
make test
```

Note: all Makefile commands support parallism, ex: `make test -j8`.

* FiberFS supports both runtime and development assertions via `assert()` and `assert_dev()`.
* FiberFS supports reference counting and memory lifetime safety via `fbr_magic_check()`.
* All memory accesses use bounds checking, assertions, and memory safety checks.
* FiberFS has a scriptable testing harness allowing for full userspace access to filesystem operations.
* All filesystem features have concurrent access tests.
* Gcov is used to provide testing code coverage reports: `make gcov` (`make gcov -j8`).
* The entire test suite can be run thru valgrind for a complete safety and leak report: `make valgrind` (`make valgrind -j4`).
