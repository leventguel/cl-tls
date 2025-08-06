#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CLIENT_HELLO_TYPE 0x01
#define TLS_VERSION 0x0303  // TLS 1.2

// Define some common cipher suites for example purposes
#define TLS_RSA_WITH_AES_128_CBC_SHA 0x002F
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 0xC013

void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

// Function to generate random data (used for Random and SessionID)
void generate_random_data(unsigned char *buffer, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        perror("Unable to open /dev/urandom");
        exit(1);
    }
    fread(buffer, 1, len, f);
    fclose(f);
}

// Function to construct the ClientHello message
void build_client_hello(unsigned char *client_hello) {
    size_t offset = 0;
    
    // Message Type (1 byte)
    client_hello[offset++] = CLIENT_HELLO_TYPE;
    
    // ProtocolVersion (2 bytes)
    client_hello[offset++] = (TLS_VERSION >> 8) & 0xFF;
    client_hello[offset++] = TLS_VERSION & 0xFF;

    // Random (32 bytes)
    unsigned char random[32];
    generate_random_data(random, sizeof(random));
    memcpy(&client_hello[offset], random, sizeof(random));
    offset += sizeof(random);

    // Session ID Length (1 byte) and Session ID (0 bytes)
    client_hello[offset++] = 0;  // Length of Session ID
    // No Session ID bytes to copy
    
    // Cipher Suites Length (2 bytes)
    unsigned short cipher_suites[] = {
        TLS_RSA_WITH_AES_128_CBC_SHA,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    };
    size_t num_cipher_suites = sizeof(cipher_suites) / sizeof(cipher_suites[0]);
    client_hello[offset++] = (num_cipher_suites * 2) >> 8;  // High byte of length
    client_hello[offset++] = (num_cipher_suites * 2) & 0xFF;  // Low byte of length
    
    // Cipher Suites (2 bytes each)
    for (size_t i = 0; i < num_cipher_suites; i++) {
        client_hello[offset++] = (cipher_suites[i] >> 8) & 0xFF;
        client_hello[offset++] = cipher_suites[i] & 0xFF;
    }

    // Compression Methods Length (1 byte)
    client_hello[offset++] = 1;
    // Compression Methods (1 byte) - no compression
    client_hello[offset++] = 0x00;  // NULL compression

    // Extensions Length (2 bytes)
    client_hello[offset++] = 0x00;
    client_hello[offset++] = 0x00;

    // Total Length of the message (can be calculated, but omitted for simplicity here)
    
    printf("ClientHello Message:\n");
    print_hex(client_hello, offset);
}

int main() {
    unsigned char client_hello[256];
    build_client_hello(client_hello);

    return 0;
}
