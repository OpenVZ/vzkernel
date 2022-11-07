PROGS := tm-resched-dscr tm-syscall

all: $(PROGS)

$(PROGS): ../harness.c

tm-syscall: tm-syscall-asm.S ../utils.c
tm-syscall: CFLAGS += -mhtm -I../../../../../usr/include

run_tests: all
	@-for PROG in $(PROGS); do \
		./$$PROG; \
	done;

clean:
	rm -f $(PROGS) *.o

.PHONY: all run_tests clean
