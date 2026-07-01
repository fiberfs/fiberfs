# FiberFS

FiberFS is a POSIX filesystem that uses S3 compatible storage as a backend.

For more information, please visit [fiberfs.io](https://fiberfs.io/).

## Building

```
make
```

Note: all Makefile commands support parallelism, ex: `make -j4`.

## Running

First make a fiberfs.conf file. At minimum, it just needs to define your S3 endpoint:

```
S3_HOST = my-bucket.s3.region123.cloud-provider.com
S3_REGION = region123
S3_ACCESS_KEY = ACCESS_KEY_STRING
S3_SECRET_KEY = SECRET_KEY_STRING
```

Next run the FiberFS binary to mount the S3 endpoint:

```
./fiberfs [fiberfs.conf] [mount_point]
```

After FiberFS is up and running, you can view the internal logs with:

```
./fiberfs_log [mount_point]
```

For more information, please visit [Building and Running FiberFS](https://fiberfs.io/content/building_and_running_fiberfs).

## Testing and Safety

```
make test
```

Note: all Makefile commands support parallelism, ex: `make test -j8`.

* FiberFS supports both runtime and development assertions via `assert()` and `assert_dev()`.
* FiberFS supports reference counting and memory lifetime safety via `fbr_magic_check()`.
* All memory accesses use bounds checking, assertions, and memory safety checks (best effort).
* FiberFS has a scriptable testing harness allowing for full userspace access to filesystem operations.
* All filesystem features have concurrent access tests (best effort).
* Gcov is used to provide testing code coverage reports: `make gcov` `-j8`
* The entire test suite can be run thru valgrind for a complete safety and leak report: `make valgrind` `-j4`
