# Nome do executável
TARGET = hash160_checker

# Arquivo fonte
SRC = hash160_checker.cpp

# Compilador e flags
CXX = g++
CXXFLAGS = -O3 -march=native -std=c++17
LDFLAGS = -lsecp256k1 -lcrypto -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib

# Regra padrão
all: $(TARGET)

# Regras para compilar o programa
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Limpeza
clean:
	rm -f $(TARGET)
