CXX=g++
CXXFLAGS=-g --std=c++2a -I/home/elerer/cryptopp-CRYPTOPP_8_9_0/
LIBS=/home/elerer/cryptopp-CRYPTOPP_8_9_0/libcryptopp.a
SOURCE=./main.cpp
TARGET=main

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

clean:
	rm -f $(TARGET)

