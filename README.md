# AVXTO Wallet Manager

A native Qt 6 desktop application for generating and managing 24-word BIP-39
mnemonic wallets. Each wallet is a single GPG-encrypted `.bin` file in a
working directory of your choosing. Unlocked wallets are held in memory as
AES-256-GCM ciphertext under a per-session password, and can be read back over
a loopback-only JSON-RPC endpoint.

## How it works

- **At rest** — a wallet is a `.bin` file encrypted with `gpg` to a key you
  pick from your own keyring. That key is the real security boundary.
- **In memory** — when you open a wallet, the application generates a fresh
  256-bit session password and immediately re-encrypts the mnemonic with
  AES-256-GCM (OpenSSL). The plaintext is wiped; from that point the mnemonic
  exists in the process only as ciphertext.
- **On the wire** — a JSON-RPC 2.0 `read` method on `127.0.0.1`, authenticated
  by the session password. A wrong password gets `403 denied`.

The full mnemonic is never displayed in the window. The UI shows the file name,
the first and last word, and the session password.

## Requirements

| Component | Version |
|-----------|---------|
| Qt        | 6.11.2 (widgets, network) |
| CMake     | 3.24+ |
| OpenSSL   | 3.0+ (libcrypto) |
| GnuPG     | 2.x, on `PATH`, with at least one secret key |
| Compiler  | C++23 |

## Building

```sh
./scripts/build.sh
./scripts/run.sh
```

`build.sh` auto-detects Qt (via `qmake` on `PATH`, then by searching `~/Qt`
for the newest 6.x kit) and writes what it finds into `CMakeUserPresets.json`
— a gitignored `dev` preset, inheriting the tracked, machine-independent
[CMakePresets.json](CMakePresets.json), that pins your Qt location, generator
and build type. `run.sh` builds if needed and launches the result. Both
accept `--clean` and `--debug`; run either with `--help` for the full list of
flags and environment overrides.

Run `build.sh` once (and again whenever your Qt install changes) and **VS
Code's CMake Tools picks up the same `dev` preset automatically** — no
environment variables to export, in a shell profile or anywhere else. A
plain script can't make an `export` stick in your interactive shell anyway
(it only affects its own subprocess); presets are the actual cross-tool
mechanism for this, which is why [.vscode/settings.json](.vscode/settings.json)
has no machine-specific paths of its own and is safe to share between
platforms.

To point at a specific Qt install instead of relying on auto-detection:

```sh
CMAKE_PREFIX_PATH="$HOME/Qt/6.11.2/gcc_64" ./scripts/build.sh   # Linux
CMAKE_PREFIX_PATH="$HOME/Qt/6.11.2/macos"  ./scripts/build.sh   # macOS
```

If your Qt is older than the 6.11.2 the project asks for by default (only
Qt 6.5+ API is used, so this is safe), also set `AVXTO_QT_MIN_VERSION`, e.g.
`AVXTO_QT_MIN_VERSION=6.9.0 ./scripts/build.sh`.

On macOS the build picks up a Homebrew or MacPorts OpenSSL 3 automatically;
the system `openssl` is LibreSSL and will not do. Override with
`OPENSSL_ROOT_DIR` if needed; Linux's system OpenSSL 3 is normally found with
no configuration at all.

Calling CMake directly still works, either via the generated preset:

```sh
cmake --preset dev
cmake --build --preset dev
```

or fully manually, bypassing presets entirely:

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/path/to/Qt/6.11.2/macos
cmake --build build
```

## Using it

1. **Set a working directory.** Every `.bin` in it is listed.
2. **New Wallet…** — pick a name and the GPG key to encrypt to. The dropdown
   defaults to keys whose secret half is on this machine, because a wallet
   encrypted to a key you cannot decrypt is unrecoverable. A fresh 24-word
   mnemonic is generated from OpenSSL's CSPRNG and written as `<name>.bin`
   with mode `0600`.
3. **Import…** (File → Import Mnemonic…, `Ctrl+Shift+I`) — save a mnemonic
   you already have. Same name and GPG key choice as above, plus a masked
   entry field for the 12–24 words. The words are never echoed: typos are
   reported by word position, and a mnemonic with a bad BIP-39 checksum is
   refused unless you explicitly tick the override. The result is an ordinary
   `<name>.bin`, indistinguishable from a generated one.
4. **Double-click a wallet** to decrypt it. Your own `gpg-agent` handles the
   passphrase prompt — this application never sees it.
5. The **session password** appears once the wallet is open. Closing the wallet
   revokes it immediately.

## JSON-RPC endpoint

The port is chosen by the OS at startup and shown in the window.

```sh
curl -s -X POST http://127.0.0.1:<port>/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"read","params":{"password":"<session-password>"}}'
```

```json
{"jsonrpc":"2.0","id":1,
 "result":{"wallet":"treasury-cold.bin",
           "mnemonic":"abandon abandon ... art",
           "wordCount":24,"firstWord":"abandon","lastWord":"art"}}
```

`params` also accepts the positional form `["<password>"]`, and an optional
`wallet` field that narrows the request to one file.

| Condition | Response |
|---|---|
| Correct session password | `200` with `result.mnemonic` |
| Wrong / missing password | `403` `{"error":{"code":-32001,"message":"denied"}}` |
| >10 failures in 60s | `429` |
| Unknown method | `200` with JSON-RPC `-32601` |
| Malformed JSON | `400` |
| Non-POST | `405` |

`scripts/rpc-demo.sh <port> <password>` wraps the above.

## Security notes

The endpoint is **plaintext HTTP on loopback**. Any process running as your
user can reach it; the session password is the only thing gating it. The
in-memory encryption is defence in depth — it keeps the mnemonic out of crash
dumps and swapped pages — but it is not protection against an attacker who can
read this process's memory, since the session password lives in the same
address space.

`notes/initiallog.txt` has the full threat model, the cryptographic rationale,
and the known gaps.

## Licence

BSD 3-Clause. See [LICENSE](LICENSE).

## Contact

@REKTbuildr on X and Telegram