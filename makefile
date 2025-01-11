# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -w

# Source files
UMBREON_SRC = main_umbreon.c umbreon.c forkskinny.c skinny_round.c helpers.c
PAEF_SRC = main_paef.c paef.c forkskinny.c skinny_round.c helpers.c

# Output binary
UMBREON_OUT = umbreon
PAEF_OUT = paef

# Default target: Build the program
all: $(UMBREON_OUT) $(PAEF_OUT)

# Link the object files and generate the output
$(UMBREON_OUT): $(UMBREON_SRC)
	$(CC) $(CFLAGS) $(UMBREON_SRC) -o $(UMBREON_OUT)

$(PAEF_OUT): $(PAEF_SRC)
	$(CC) $(CFLAGS) $(PAEF_SRC) -o $(PAEF_OUT)

# Clean up generated files
clean:
	rm -f $(UMBREON_OUT) *.o
	rm -f $(PAEF_OUT) *.o

# Phony targets
.PHONY: all clean

