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

#define MESSAGE_CHUNK_SIZE    64
#define MAX_DOMAIN_LENGTH     64
#define MAX_URI_LENGTH        64
#define MAX_VERSION_LENGTH    5
#define MAX_NONCE_LENGTH      32
#define MAX_DATETIME_LENGTH   32
#define MAX_FIELD_NAME_LENGTH 18

static unsigned char const BSM_SIGN_MAGIC[] = {'\x18', 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
                                               'S',    'i', 'g', 'n', 'e', 'd', ' ', 'M', 'e',
                                               's',    's', 'a', 'g', 'e', ':', '\n'};

typedef struct {
    const char *name;
    size_t name_length;
    char *output;
    size_t max_length;
    bool *found_flag;
} ERC4361Field;

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

    if (bip32_path_len > MAX_BIP32_PATH_STEPS || message_length >= (1LL << 32)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    char path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1] = "(Master key)";
    if (bip32_path_len > 0) {
        bip32_path_format(bip32_path, bip32_path_len, path_str, sizeof(path_str));
    }

    cx_sha256_t msg_hash_context;    // used to compute sha256(message)
    cx_sha256_t bsm_digest_context;  // used to compute the Bitcoin Message Signing digest
    cx_sha256_init(&msg_hash_context);
    cx_sha256_init(&bsm_digest_context);

    crypto_hash_update(&bsm_digest_context.header, BSM_SIGN_MAGIC, sizeof(BSM_SIGN_MAGIC));
    crypto_hash_update_varint(&bsm_digest_context.header, message_length);

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
    ERC4361Field fields[] = {
        {"URI: ", 5, uri, MAX_URI_LENGTH, &uri_found},
        {"Version: ", 9, version, MAX_VERSION_LENGTH, &version_found},
        {"Nonce: ", 7, nonce, MAX_NONCE_LENGTH, &nonce_found},
        {"Issued At: ", 11, issued_at, MAX_DATETIME_LENGTH, &issued_at_found},
        {"Expiration Time: ", 17, expiration_time, MAX_DATETIME_LENGTH, &expiration_time_found},
    };
    const size_t num_fields = sizeof(fields) / sizeof(fields[0]);

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
            crypto_hash_update(&msg_hash_context.header, message_chunk, chunk_len);
            crypto_hash_update(&bsm_digest_context.header, message_chunk, chunk_len);

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
            for (size_t i = 0; i < num_fields; i++) {
                ERC4361Field *field = &fields[i];
                if (!*field->found_flag && parsing_buffer_len >= field->name_length &&
                    memcmp(parsing_buffer, field->name, field->name_length) == 0) {
                    size_t field_length = parse_field(parsing_buffer + field->name_length,
                                                      parsing_buffer_len - field->name_length,
                                                      field->output,
                                                      field->max_length);
                    total_bytes_read += field_length + field->name_length;
                    *field->found_flag = true;
                    PRINTF("%s%s\n", field->name, field->output);
                    break;
                }
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

    uint8_t message_hash[32];
    uint8_t bsm_digest[32];

    crypto_hash_digest(&msg_hash_context.header, message_hash, 32);
    crypto_hash_digest(&bsm_digest_context.header, bsm_digest, 32);
    cx_hash_sha256(bsm_digest, 32, bsm_digest, 32);

    char message_hash_str[MESSAGE_CHUNK_SIZE + 1];
    for (int i = 0; i < MESSAGE_CHUNK_SIZE / 2; i++) {
        snprintf(message_hash_str + 2 * i, 3, "%02X", message_hash[i]);
    }

#ifndef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    // DISPLAY UI
    if (!ui_validate_erc4361_data_and_confirm(dc,
                                              domain,
                                              address,
                                              uri,
                                              version,
                                              nonce,
                                              issued_at,
                                              expiration_time)) {
        SEND_SW(dc, SW_DENY);
        ui_post_processing_confirm_message(dc, false);
        return;
    }
#endif
    uint8_t sig[MAX_DER_SIG_LEN];

    uint32_t info;
    int sig_len = crypto_ecdsa_sign_sha256_hash_with_key(bip32_path,
                                                         bip32_path_len,
                                                         bsm_digest,
                                                         NULL,
                                                         sig,
                                                         &info);
    if (sig_len < 0) {
        // unexpected error when signing
        SEND_SW(dc, SW_BAD_STATE);
        // ui_post_processing_confirm_erc4361_message(dc, false);
        return;
    }

    {
        // convert signature to the standard Bitcoin format, always 65 bytes long

        uint8_t result[65];
        memset(result, 0, sizeof(result));

        // # Format signature into standard bitcoin format
        int r_length = sig[3];
        int s_length = sig[4 + r_length + 1];

        if (r_length > 33 || s_length > 33) {
            SEND_SW(dc, SW_BAD_STATE);  // can never happen
            // ui_post_processing_confirm_erc4361_message(dc, false);
            return;
        }

        // Write s, r, and the first byte in reverse order, as the two loops will underflow by 1
        // byte (that needs to be discarded) when s_length and r_length (respectively) are equal
        // to 33.
        for (int i = s_length - 1; i >= 0; --i) {
            result[1 + 32 + 32 - s_length + i] = sig[4 + r_length + 2 + i];
        }
        for (int i = r_length - 1; i >= 0; --i) {
            result[1 + 32 - r_length + i] = sig[4 + i];
        }
        result[0] = 27 + 4 + ((info & CX_ECCINFO_PARITY_ODD) ? 1 : 0);

        SEND_RESPONSE(dc, result, sizeof(result), SW_OK);
        ui_post_processing_confirm_message(dc, true);
        return;
    }
}
