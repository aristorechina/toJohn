# toJohn

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=plastic)](https://github.com/aristorechina/toJohn/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/tojohn?logo=rust&logoColor=white&style=plastic&color=orange)](https://crates.io/crates/tojohn)
[![GitHub](https://img.shields.io/badge/Github-toJohn-181716?style=plastic&logo=github&logoColor=white)](https://github.com/aristorechina/toJohn)
[![Latest Release](https://img.shields.io/github/v/release/aristorechina/toJohn?sort=semver&style=plastic&color=brightgreen)](https://github.com/aristorechina/toJohn/releases/latest)

English | [简体中文](https://github.com/aristorechina/toJohn/blob/main/README_CN.md)

**toJohn** is an all-in-one password-hash extraction tool: it pulls crackable password hashes out of 100+ file formats and renders them as unified hash lines, ready to load into password crackers such as John the Ripper and hashcat.

## Features

- **100+ formats**: encrypted volumes, archives, databases, wallets, office documents, certificates & keys, network captures
- **Unified CLI**: automatic format detection (best-effort content sniffing), recursive directory scanning, batch processing, output redirection
- **Exact output**: every format's output is pinned byte for byte by golden tests, guaranteeing agreement with the format's canonical hash line
- **Pure Rust**: low-level parsing for ASN.1/DER, OLE2/CFB, ZIP, XML, pcap and more is built in — no external scripts at runtime

## Building

Rust 1.87+ is required (2021 edition; uses newer APIs such as `is_multiple_of`). `rusqlite` is built with the bundled feature, so a local C compiler is needed.

```sh
cargo build --release
# output: target/release/tojohn(.exe)
```

Or install straight onto your PATH:

```sh
cargo install --path crates/tojohn-cli
```

## Usage

```text
tojohn [OPTIONS] <FILE>...
```

Common examples:

```sh
# detect the format automatically and extract
tojohn backup.7z

# force a format (for inputs where detection is ambiguous)
tojohn -f zip encrypted.zip

# scan a directory recursively, write to a file, keep going after per-file errors
tojohn -r dumps/ -o hashes.txt --keep-going

# list all supported formats / per-format details
tojohn --list-formats
tojohn --list-details

# inline text input (text-based formats, e.g. ansible-vault)
tojohn --text -f ansible '$ANSIBLE_VAULT;1.1;AES256;...'
```

### Options

| Option | Description |
| --- | --- |
| `-f, --format <name>` | Force a format (names from `--list-formats`) |
| `-r, --recursive` | Scan directories recursively |
| `-k, --keyfile <path>` | Attach a keyfile |
| `-o, --output <path>` | Write to a file instead of stdout |
| `--text <text>` | Inline text input (requires `-f`) |
| `--keep-going` | Continue after per-file errors in batch mode |
| `-q, --quiet` | Suppress the per-file summary on stderr |
| `--list-formats` | List all supported formats and exit |
| `--list-details` | List format details (detection capability, description) and exit |

Detection walks the registered formats in a fixed priority order, trying each format's content sniffer; force a format with `-f` for ambiguous inputs.

## Testing

```sh
cargo test
```

The suite is 15 unit tests + 142 golden tests. Golden cases live in [`fixtures/`](https://github.com/aristorechina/toJohn/tree/main/fixtures): each case = an input sample + its expected output (`expected.txt`), compared byte for byte against the extraction result. This is the project's acceptance standard for correctness — after any code change, run the suite once to confirm that every format's output is unchanged. Style and naming rules: [CONVENTIONS.md](https://github.com/aristorechina/toJohn/blob/main/CONVENTIONS.md).

## Project layout

```text
crates/
  tojohn/        core library: 100+ format modules + shared parsers (ASN.1, OLE2, ZIP, XML, pcap)
  tojohn-cli/    command-line front end
fixtures/        golden test data
CONVENTIONS.md   code style and naming rules
```

## License

[Apache-2.0](https://github.com/aristorechina/toJohn/blob/main/LICENSE) © [Aristore](https://github.com/aristorechina)

## Acknowledgements

- [openwall/john](https://github.com/openwall/john) — the hash-line output formats this tool emits are defined by the John the Ripper project
- [ivanmrsulja/keepass2john](https://github.com/ivanmrsulja/keepass2john) — reference implementation for the KDBX4 hash extraction
