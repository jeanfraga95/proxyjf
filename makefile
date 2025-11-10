CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
TARGET = proxy
SOURCES = main.c
INSTALL_PATH = /opt/rustyproxy

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

install: $(TARGET)
	sudo mkdir -p $(INSTALL_PATH)
	sudo cp $(TARGET) $(INSTALL_PATH)/
	sudo cp menu.sh $(INSTALL_PATH)/menu
	sudo chmod +x $(INSTALL_PATH)/proxy $(INSTALL_PATH)/menu
	sudo ln -sf $(INSTALL_PATH)/menu /usr/local/bin/rustyproxy

clean:
	rm -f $(TARGET)
