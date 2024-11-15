# Hash160 Checker PUZZLE#67

Este programa verifica chaves privadas dentro de um intervalo, calcula o Hash160 de suas respectivas chaves públicas comprimidas e encontra uma chave alvo. Está ajustado para procurar a chave do Puzzle#67

## Requisitos

Para compilar e executar o programa, você precisa:
- **Compilador C++ com suporte a C++17** (g++ ou clang++)
- **Biblioteca secp256k1** instalada
- **OpenSSL** instalado

### Instalação das Dependências

#### 1. Instale o OpenSSL

- No Ubuntu/Debian:
  ```bash
  sudo apt-get install libssl-dev

- No macOS (usando Homebrew):
  ```bash
  brew install openssl

#### 2. Instale a Biblioteca secp256k1

- Clone e compile a biblioteca secp256k1:
   ```bash
  git clone https://github.com/bitcoin-core/secp256k1.git
  cd secp256k1
  ./autogen.sh
  ./configure
  make
  sudo make install

### Como Compilar

#### 1. Clone o repositório:
  
  ```bash
  git clone https://github.com/seu-usuario/hash160_checker.git
  cd hash160_checker

#### 2. Compile o programa:

  ```bash
  g++ -O3 -march=native -std=c++17 -o hash160_checker hash160_checker.cpp -lsecp256k1 -lcrypto -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib

### Como Executar

  ```bash
  ./hash160_checker
