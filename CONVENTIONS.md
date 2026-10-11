# Code Conventions

Style and naming rules for `tojohn` / `tojohn-cli`. The golden fixtures under `fixtures/` pin the output byte for byte, and `cargo test` is the acceptance gate for every change.

## Naming

- **Types and traits**: PascalCase, named after the artifact or record they model (`HccapRecord`, `KdbxParams`, `ProtectorMaterial`).
- **Functions**: snake_case verb phrases by role:
  - `extract_*` — the top-level branch for one container or version (`extract_v1`, `extract_kdbx`)
  - `parse_*` / `read_*` — byte-level decoding of records, headers, fields (`parse_hccapx`, `read_header`)
  - `render_*` / `push_*` / `emit_*` — output formatting (`render_hccapx_record`, `push_crypt_block`, `emit_b64_quad`)
- **Variables**: full English words; a short name is fine inside a tiny loop body where its meaning is obvious from the line.
- **Byte fields**: named for their role in the format's own specification (`stream_start_bytes`, `master_seed`, `salt`, `keyver`). When a format has a public specification, its terminology wins.
- **Constants**: SCREAMING_SNAKE with a doc comment stating the meaning in the format (`FIELD_END_OF_HEADER`, `CIPHER_AES`, `BASE_PROFILE_SIGNATURE`). A magic offset used once may stay inline with a comment.
- **Booleans**: named as predicates (`is_legacy`, `is_entry`, `repeating`, `found`).

## Byte parsing

- Decode integers with `try_into()` plus `from_le_bytes` / `from_be_bytes`; slice each record into named fields once, then work with the fields.
- Advance a single cursor `pos` by whole-field steps; when the same fields repeat, move the cursor logic into a `Reader`-style helper (see `putty.rs`).
- Bounds-check with `get()` and slices; reserve `expect()` for programmer-error invariants whose precondition is already validated.

## Comments

- Doc comments describe what the format requires and what the code does. Cite public format specifications where they exist.
- Code files name only this project, public format specifications, and the hash-format tokens themselves.
- Comments explain constraints the code cannot show.

## Error messages

- Lowercase throughout; the message names the structural problem.

## Behavior invariants

- Hash lines are the contract: golden fixtures stay byte-identical.
- `cargo clippy --workspace --all-targets` stays clean under the workspace's warnings-denied lints.
- Format modules reach stdout only through returned `HashLine` values; the one sanctioned exception is `bitlocker`'s documented progress-line contract.