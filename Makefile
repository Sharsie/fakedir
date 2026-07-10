libfakedir.dylib: fakedir.o trivial_replacements.o execve.o pathresolve.o
	$(CC) $(CFLAGS) -shared $^ -o $@

fakedir.o: fakedir.c common.h execve.h
trivial_replacements.o: trivial_replacements.c common.h
execve.o: execve.c common.h
pathresolve.o: pathresolve.c common.h

# Unit tests for the path resolution logic; runs on any POSIX host,
# no macOS required.
check: tests/test_pathresolve
	./tests/test_pathresolve

tests/test_pathresolve: tests/test_pathresolve.c pathresolve.c common.h
	$(CC) $(CFLAGS) -g -I. -o $@ tests/test_pathresolve.c pathresolve.c

clean:
	rm -f *.o libfakedir.dylib tests/test_pathresolve

.PHONY: check clean
