# End-to-end Tests

These tests are implemented in Python and can be executed using either the [Speculos](https://github.com/LedgerHQ/speculos) emulator or a physical Ledger Nano X/SP/Flex or Stax device. The tests require an x86_64 architecture.

Note: If you're using the Ledger Developer Extension, some tests (those containing "e2e" in their names) may not run properly due to missing libraries in the Docker image.

All the commands in this folder are meant to be ran from the `tests` folder, not from the root.

Python dependencies are listed in [requirements.txt](requirements.txt), install them using [pip](https://pypi.org/project/pip/).

```
pip install -r requirements.txt
```

Some tests require the `bitcoind 22.0` binary to be in the `$PATH` variable, or alternatively to be set as the `BITCOIND` environment variable in the shell running the tests:

```
export BITCOIND=/path/to/my/bitcoind
```

You may also need to install the following dependencies to run the end to end tests:

```
sudo apt-get update && sudo apt-get install -y qemu-user-static tesseract-ocr libtesseract-dev
pip install -U pip setuptools
```

## Launch with Speculos

Build the app as normal from the root folder. For convenience, you probably want to enable DEBUG:

```
DEBUG=1 make
```

Then run all the tests from this folder, specifying the device: nanox, nanosp, stax, flex, or all:

```
pytest --device yourdevice
```

You can enable the screen display with the option `--display`

## Launch with your Nano S/X/SP or Stax

Compile and install the app on your device as normal.

To run the tests on your Ledger device you also need to install an optional dependency

```
pip install ledgercomm[hid]
```

Be sure to have you device connected through USB (without any other software interacting with it) and run

```
pytest --device yourdevice --backend ledgercomm
```
