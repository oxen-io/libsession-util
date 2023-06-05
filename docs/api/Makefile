H_FILES = $(wildcard ../../include/session/config/*.h)
HPP_FILES = $(wildcard ../../include/session/config/*.hpp)

hpp-docs:
	./make-docs.sh $(HPP_FILES)

h-docs:
	./make-docs.sh $(H_FILES)

.PHONY: run
run:
	docsify serve api


.PHONY: clean
clean:
	rm -rf ./api
