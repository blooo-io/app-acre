#include <stdint.h>
#include <string.h>

#include "boilerplate/io.h"
#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../common/bip32.h"
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "lib/get_merkle_leaf_element.h"

#include "handlers.h"

#define MESSAGE_CHUNK_SIZE 64
#define MAX_DOMAIN_LENGTH  64
#define MAX_URI_LENGTH     64

// static unsigned char const BSM_SIGN_MAGIC[] = {'\x18', 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
//                                                'S',    'i', 'g', 'n', 'e', 'd', ' ', 'M', 'e',
//                                                's',    's', 'a', 'g', 'e', ':', '\n'};

static size_t parse_domain(const uint8_t *buffer, size_t buffer_len, char *domain) {
    size_t domain_length = 0;
    while (domain_length < buffer_len && domain_length < MAX_DOMAIN_LENGTH - 1) {
        if (buffer[domain_length] == ' ' || buffer[domain_length] == '\n') {
            break;
        }
        domain_length++;
    }

    memcpy(domain, buffer, domain_length);
    domain[domain_length] = '\0';

    return domain_length;
}

static size_t parse_address(const uint8_t *buffer, size_t buffer_len, char *address) {
    size_t address_length = 0;
    while (address_length < buffer_len && address_length < MAX_ADDRESS_LENGTH_STR - 1) {
        if (buffer[address_length] == ' ' || buffer[address_length] == '\n') {
            break;
        }
        address_length++;
    }

    memcpy(address, buffer, address_length);
    address[address_length] = '\0';

    return address_length;
}

static size_t parse_uri(const uint8_t *buffer, size_t buffer_len, char *uri) {
    size_t uri_length = 0;
    while (uri_length < buffer_len && uri_length < MAX_URI_LENGTH - 1) {
        if (buffer[uri_length] == '\n' || buffer[uri_length] == '\0' || buffer[uri_length] == ' ') {
            break;
        }
        uri_length++;
    }

    memcpy(uri, buffer, uri_length);
    uri[uri_length] = '\0';

    return uri_length;
}

static bool has_newline(const char *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (buffer[i] == '\n') {
            return true;
        }
    }
    return false;
}

void handler_sign_erc4361_message(dispatcher_context_t *dc, uint8_t protocol_version) {
    (void) protocol_version;

    uint8_t bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint64_t message_length;
    uint8_t message_merkle_root[32];

    if (!buffer_read_u8(&dc->read_buffer, &bip32_path_len) ||
        !buffer_read_bip32_path(&dc->read_buffer, bip32_path, bip32_path_len) ||
        !buffer_read_varint(&dc->read_buffer, &message_length) ||
        !buffer_read_bytes(&dc->read_buffer, message_merkle_root, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    size_t n_chunks = (message_length + MESSAGE_CHUNK_SIZE - 1) / MESSAGE_CHUNK_SIZE;

    uint8_t message_chunk[MESSAGE_CHUNK_SIZE];
    uint64_t total_bytes_read = 0;
    uint64_t line_start = 0;
    uint32_t current_line = 0;

    char domain[MAX_DOMAIN_LENGTH] = {0};
    char address[MAX_ADDRESS_LENGTH_STR] = {0};
    char uri[MAX_URI_LENGTH] = {0};  // Add this line

    char leftover[MESSAGE_CHUNK_SIZE] = {0};
    size_t leftover_len = 0;
    uint8_t parsing_buffer[128] = {0};
    size_t parsing_buffer_len = 0;

    bool parsing_done = false;
    bool uri_found = false;  // Add this line

    unsigned int chunk_index = 0;
    while ((chunk_index < n_chunks || total_bytes_read < message_length) && !parsing_done) {
        PRINTF("Chunk index: %u\n", chunk_index);
        int chunk_len = 0;
        if (!has_newline(leftover, leftover_len) && chunk_index < n_chunks) {
            chunk_len = call_get_merkle_leaf_element(dc,
                                                     message_merkle_root,
                                                     n_chunks,
                                                     chunk_index,
                                                     message_chunk,
                                                     sizeof(message_chunk));

            if (chunk_len < 0 || (chunk_len != MESSAGE_CHUNK_SIZE && chunk_index != n_chunks - 1)) {
                SEND_SW(dc, SW_BAD_STATE);  // should never happen
                return;
            }
            chunk_index++;  // Only increment when a new chunk is fetched
        }
        PRINTF("Total bytes read: %llu\n", total_bytes_read);

        // Copy leftover and new chunk into parsing buffer
        memset(parsing_buffer, 0, sizeof(parsing_buffer));
        memcpy(parsing_buffer, leftover, leftover_len);
        memcpy(parsing_buffer + leftover_len, message_chunk, chunk_len);
        parsing_buffer_len = leftover_len + chunk_len;
        leftover_len = 0;

        if (current_line == 0) {
            size_t domain_length = parse_domain(parsing_buffer, parsing_buffer_len, domain);
            total_bytes_read += domain_length - 1;  // -1 to skip the '\0' after the domain
            PRINTF("Domain: %s\n", domain);
        }

        if (current_line == 1) {
            size_t address_length = parse_address(parsing_buffer, parsing_buffer_len, address);
            total_bytes_read += address_length - 1;  // -1 to skip the '\0' after the address
            PRINTF("Address: %s\n", address);
        }

        // Line 2 and 3 are empty
        if (current_line >= 4) {
            // Compare the start of the line with "URI"
            if (!uri_found && parsing_buffer_len >= 5 && memcmp(parsing_buffer, "URI: ", 5) == 0) {
                size_t uri_length = parse_uri(parsing_buffer + 5, parsing_buffer_len - 5, uri);
                total_bytes_read += uri_length + 5;  // +5 for "URI: "
                uri_found = true;
                PRINTF("URI: %s\n", uri);
            }
        }

        for (size_t j = total_bytes_read - line_start; j < parsing_buffer_len; j++) {
            total_bytes_read++;
            PRINTF("Total bytes read: %llu\n", total_bytes_read);

            if (parsing_buffer[j] == '\n') {
                // Save leftover for next chunk
                leftover_len = parsing_buffer_len - (total_bytes_read - line_start);
                memcpy(leftover, parsing_buffer + parsing_buffer_len - leftover_len, leftover_len);
                // TODO: Handle the case where the line is too long
                current_line++;
                line_start = total_bytes_read;
                break;
            }

            if (total_bytes_read >= message_length || parsing_buffer[j] == '\0') {
                parsing_done = true;
                PRINTF("Parsing done: %d\n", parsing_done);
                break;
            }
        }
    }

    // TODO: Implement the rest of the sign_erc4361_message logic here

    // For now, we'll just send a "ok" status word
    SEND_SW(dc, SW_OK);
}
