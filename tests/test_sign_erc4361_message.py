import pytest
from ledger_bitcoin import Client
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient
from .instructions import erc4361_message_instruction_approve

def test_sign_erc4361_message(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    message = "stake.acre.fi wants you to sign in with your Bitcoin account:\nbc1q8fq0vs2f9g52cuk8px9f664qs0j7vtmx3r7wvx\n\n\nURI: https://stake.acre.fi\nVersion: 1\nNonce: cw73Kfdfn1lY42Jj8\nIssued At: 2024-10-01T11:03:05.707Z\nExpiration Time: 2024-10-08T11:03:05.707Z"
    path = "m/44'/1'/0'/0/0"
    client.sign_erc4361_message(message, path, navigator,
                        instructions=erc4361_message_instruction_approve(firmware, save_screenshot=True),
                        testname=test_name)