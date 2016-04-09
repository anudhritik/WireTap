CC = g++
CPFLAGS = -g -Wall -Wextra
LDFLAGS = -lpcap

# all source files
SRC = wt_client.cpp wt_lib.cpp
# all object files
OBJ = $(SRC:.cpp=.o)
# executable output file
BIN = wiretap

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) $(OBJ) -o $(BIN)

%.o: %.cpp
	$(CC) $(CPFLAGS) -c $< -o $@

$(SRC):

# remove object files, program executable
clean:
	rm -f *.o wiretap
