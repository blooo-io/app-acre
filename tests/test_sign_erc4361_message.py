import pytest
from ledger_bitcoin import Client
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient
from .instructions import erc4361_message_instruction_approve

def test_sign_erc4361_message(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    message = "stake.acre.fi wants you to sign in with your Bitcoin account:\nbc1q8fq0vs2f9g52cuk8px9f664qs0j7vtmx3r7wvx\n\n\nURI: https://stake.acre.fi\nVersion: 1\nNonce: cw73Kfdfn1lY42Jj8\nIssued At: 2024-10-01T11:03:05.707Z\nExpiration Time: 2024-10-08T11:03:05.707Z"
    path = "m/44'/0'/0'/0/0"
    result = client.sign_erc4361_message(message, path, navigator,
                        instructions=erc4361_message_instruction_approve(firmware, save_screenshot=True),
                        testname=test_name)
    assert result == "IPMP+RMxuEDMl1YLRo2dzgZHr773/XSBl3NyGglpBdp+Zko843TxlR5AIi1DPNjWl33eCK9jIKzI3ZD6Ne0cjtg="

def test_sign_erc4361_message_testnet_message(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    message = "stake.test.acre.fi wants you to sign in with your Bitcoin account:\n2N1LKgFZMgJWuHuzmRWX6uYMKyAQn6KHKw7\n\n\nURI: https://stake.test.acre.fi\nVersion: 1\nNonce: WrHviCXAslNNeNtcD\nIssued At: 2024-10-01T11:00:23.816Z\nExpiration Time: 2024-10-08T11:00:23.816Z"
    path = "m/44'/1'/0'/0/0"
    result = client.sign_erc4361_message(message, path, navigator,
                        instructions=erc4361_message_instruction_approve(firmware, save_screenshot=True),
                        testname=test_name)
    assert result == "H/uxf24nzGCwPmR27m6Lcp8ol0krcfAf4NcJHmStMeFGBInjIvvMi0VrOLOkfjqxKWdl7I+9Q3mlNsOSSLCMRTw="
    
def test_sign_erc4361_message_dev_env(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    message = "deploy-preview-742--acre-dapp-testnet.netlify.app wants you to sign in with your Bitcoin account:\n2N1LKgFZMgJWuHuzmRWX6uYMKyAQn6KHKw7\n\n\nURI: https://deploy-preview-742--acre-dapp-testnet.netlify.app\nVersion: 1\nNonce: mlMwgeqdzmccZdcc7\nIssued At: 2024-10-01T11:38:46.608Z\nExpiration Time: 2024-10-08T11:38:46.608Z"
    path = "m/44'/1'/0'/0/0"
    result = client.sign_erc4361_message(message, path, navigator,
                        instructions=erc4361_message_instruction_approve(firmware, save_screenshot=True),
                        testname=test_name)
    assert result == "H+Mqper3hzLMaebKumTWVdEfQMieeDcpQedbEVbKoBI5OfjBoqy0nQysLH1jaPRyEAfBMmUYDYYtS8giYhcM7Qk="