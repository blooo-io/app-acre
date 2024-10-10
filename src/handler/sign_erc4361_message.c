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

#define MESSAGE_CHUNK_SIZE  64
#define MAX_DOMAIN_LENGTH   64
#define MAX_URI_LENGTH      64
#define MAX_VERSION_LENGTH  5
#define MAX_NONCE_LENGTH    32
#define MAX_DATETIME_LENGTH 32

// static unsigned char const BSM_SIGN_MAGIC[] = {'\x18', 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
//                                                'S',    'i', 'g', 'n', 'e', 'd', ' ', 'M', 'e',
//                                                's',    's', 'a', 'g', 'e', ':', '\n'};

static size_t parse_field(const uint8_t *buffer,
                          size_t buffer_len,
                          char *output,
                          size_t max_length) {
    size_t field_length = 0;
    while (field_length < buffer_len && field_length < max_length - 1) {
        if (buffer[field_length] == '\n' || buffer[field_length] == '\0' ||
            buffer[field_length] == ' ') {
            break;
        }
        field_length++;
    }

    memcpy(output, buffer, field_length);
    output[field_length] = '\0';

    return field_length;
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
    char uri[MAX_URI_LENGTH] = {0};
    char version[MAX_VERSION_LENGTH] = {0};
    char nonce[MAX_NONCE_LENGTH] = {0};
    char issued_at[MAX_DATETIME_LENGTH] = {0};
    char expiration_time[MAX_DATETIME_LENGTH] = {0};

    char leftover[MESSAGE_CHUNK_SIZE] = {0};
    size_t leftover_len = 0;
    uint8_t parsing_buffer[128] = {0};
    size_t parsing_buffer_len = 0;

    bool parsing_done = false;
    bool uri_found = false;
    bool version_found = false;
    bool nonce_found = false;
    bool issued_at_found = false;
    bool expiration_time_found = false;

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
            size_t domain_length =
                parse_field(parsing_buffer, parsing_buffer_len, domain, MAX_DOMAIN_LENGTH);
            total_bytes_read += domain_length;
            PRINTF("Domain: %s\n", domain);
        }

        if (current_line == 1) {
            size_t address_length =
                parse_field(parsing_buffer, parsing_buffer_len, address, MAX_ADDRESS_LENGTH_STR);
            total_bytes_read += address_length;
            PRINTF("Address: %s\n", address);
        }

        // Lines 2 and 3 are empty
        if (current_line >= 4) {
            if (!uri_found && parsing_buffer_len >= 5 && memcmp(parsing_buffer, "URI: ", 5) == 0) {
                size_t uri_length =
                    parse_field(parsing_buffer + 5, parsing_buffer_len - 5, uri, MAX_URI_LENGTH);
                total_bytes_read += uri_length + 5;  // +5 for "URI: "
                uri_found = true;
                PRINTF("URI: %s\n", uri);
            } else if (!version_found && parsing_buffer_len >= 9 &&
                       memcmp(parsing_buffer, "Version: ", 9) == 0) {
                size_t version_length = parse_field(parsing_buffer + 9,
                                                    parsing_buffer_len - 9,
                                                    version,
                                                    MAX_VERSION_LENGTH);
                total_bytes_read += version_length + 9;  // +9 for "Version: "
                version_found = true;
                PRINTF("Version: %s\n", version);
            } else if (!nonce_found && parsing_buffer_len >= 7 &&
                       memcmp(parsing_buffer, "Nonce: ", 7) == 0) {
                size_t nonce_length = parse_field(parsing_buffer + 7,
                                                  parsing_buffer_len - 7,
                                                  nonce,
                                                  MAX_NONCE_LENGTH);
                total_bytes_read += nonce_length + 7;  // +7 for "Nonce: "
                nonce_found = true;
                PRINTF("Nonce: %s\n", nonce);
            } else if (!issued_at_found && parsing_buffer_len >= 11 &&
                       memcmp(parsing_buffer, "Issued At: ", 11) == 0) {
                size_t issued_at_length = parse_field(parsing_buffer + 11,
                                                      parsing_buffer_len - 11,
                                                      issued_at,
                                                      MAX_DATETIME_LENGTH);
                total_bytes_read += issued_at_length + 11;  // +11 for "Issued At: "
                issued_at_found = true;
                PRINTF("Issued At: %s\n", issued_at);
            } else if (!expiration_time_found && parsing_buffer_len >= 18 &&
                       memcmp(parsing_buffer, "Expiration Time: ", 17) == 0) {
                size_t expiration_time_length = parse_field(parsing_buffer + 17,
                                                            parsing_buffer_len - 17,
                                                            expiration_time,
                                                            MAX_DATETIME_LENGTH);
                total_bytes_read += expiration_time_length + 17;  // +17 for "Expiration Time: "
                expiration_time_found = true;
                PRINTF("Expiration Time: %s\n", expiration_time);
            }
        }

        // Iterate on the rest of the line
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
