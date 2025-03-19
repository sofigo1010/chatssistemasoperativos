CC = gcc
CFLAGS = -Wall -I./include -I./src/utils -I./src/users
LIBS = -lwebsockets -lcjson

# Archivos fuente
SRC = src/main.c src/utils/logger.c src/users/user_manager.c
OBJ = $(SRC:.c=.o)
TARGET = chat_server

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
