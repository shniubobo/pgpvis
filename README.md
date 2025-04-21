# pgpvis

`pgpvis` is a low-level dumper and visualizer for OpenPGP packets, offering a
hex view and a packet tree for octet-level inspection. It could be thought of as
a GUI version of `pgpdump`, `gpg --list-packets`, or `sq packet dump --hex`.

Try for yourself: \[TODO: Add link to deployment\]

> [!WARNING]
>
> This project is still work in progress, and many features are missing. Most
> noticeably, the parser currently only handles RSA public keys and subkeys, and
> user IDs. In the meantime, if you need a feature-complete dumper, use the
> above CLI tools, or [dump.sequoia-pgp.org](https://dump.sequoia-pgp.org/).

## Building and previewing

If you don't feel like using the online version of `pgpvis`, you could build it
locally.

First, you need a working [Node](https://nodejs.org/en/download) and
[Rust](https://rustup.rs/) installation, and make sure you have `pnpm` and
Rust's `wasm32-unknown-unknown` target installed:

```
corepack enable pnpm
rustup target add wasm32-unknown-unknown
```

Then, clone this repo, and do the following in the repo root:

```
pnpm i
pnpm dist
```

To preview the built artifacts:

```
cd pgpvis-ui
pnpm preview
```

Follow the instructions you see in the terminal, which should show you a local
HTTP URL.

## Contributing

TODO: Add `CONTRIBUTING.md`.

In the meantime, please follow the building instructions above.

You may also have a look at the `package.json` files, which contain linting,
testing, and building commands. Many code files in the `pgpvis-core` and
`pgpvis-ui` subfolders have detailed comments.

## Licensing

Unless otherwise stated, all files in this repository are licensed under GNU
Affero General Public License Version 3 (GNU AGPLv3).

```
pgpvis - An OpenPGP packet dumper and visualizer
Copyright (C) 2025-present  pgpvis Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

See [`LICENSE`](LICENSE) for the full license.
