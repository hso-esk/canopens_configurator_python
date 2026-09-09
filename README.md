## Quickstart

1. **Clone** or extract the repository.
2. **Build and install deps**:
   ```bash
   bash ./build_deps.sh
   pip install -r requirements.txt
   ```
3. **Configure participant with**: 
   ```bash
   python ./spsec_cli.py  -i vcan0 -k ./keys.txt -l DEBUG -p 123
   ```

## Building external crypto backend

This repo vendors crypto libraries as git submodules under `external/`.

- Initialize submodules:

  `git submodule update --init --recursive`

- Build WolfSSL (default):

  `./build_deps.sh wolfssl`

- Build MbedTLS (alternative):

  `./build_deps.sh mbedtls`

The backend selection is implemented in `external/CMakeLists.txt` via the CMake cache option `SPSEC_CRYPTO_BACKEND`.

Note: ASCON-128 support in the configurator is provided via the WolfSSL/wolfCrypt wrapper (`wolfssl_ascon.py`) and is disabled automatically when `SPSEC_CRYPTO_BACKEND=mbedtls`.
