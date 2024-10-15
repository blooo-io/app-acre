#pragma once

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_EXTENDED_PUBKEY = 0x00,
    REGISTER_WALLET = 0x02,
    GET_WALLET_ADDRESS = 0x03,
    SIGN_PSBT = 0x04,
    GET_MASTER_FINGERPRINT = 0x05,
    SIGN_MESSAGE = 0x10,
    WITHDRAW = 0x11,
    SIGN_ERC4361_MESSAGE = 0x12,
} command_e;
