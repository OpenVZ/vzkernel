TARGETS = breakpoints
TARGETS += cpu-hotplug
TARGETS += efivarfs
TARGETS += kcmp
TARGETS += livepatch
TARGETS += memfd
TARGETS += memory-hotplug
TARGETS += mqueue
TARGETS += net
TARGETS += ptrace
TARGETS += vm
TARGETS += x86
TARGETS += powerpc

all:
	for TARGET in $(TARGETS); do \
		make -C $$TARGET; \
	done;

run_tests: all
	for TARGET in $(TARGETS); do \
		make -C $$TARGET run_tests; \
	done;

clean:
	for TARGET in $(TARGETS); do \
		make -C $$TARGET clean; \
	done;
