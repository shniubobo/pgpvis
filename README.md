# pgpvis

`pgpvis` is a low-level dumper and visualizer for OpenPGP packets, offering a
hex view and a packet tree for octet-level inspection. It could be thought of as
a GUI version of `pgpdump`, `gpg --list-packets`, or `sq packet dump --hex`.

Try for yourself: [pgpvis.shniubobo.com](https://pgpvis.shniubobo.com/)

> [!WARNING]
>
> This project is still work in progress, and many features are missing. Most
> noticeably, the parser currently only handles public keys and subkeys, and
> user IDs. In the meantime, if you need a feature-complete dumper, use the
> above CLI tools, or [dump.sequoia-pgp.org](https://dump.sequoia-pgp.org/).

## Usage

### Using the release deployment

The latest tagged commit is deployed at
[pgpvis.shniubobo.com](https://pgpvis.shniubobo.com/).

### Using preview deployments

The latest commit on `master` is deployed at
[master.pgpvis.pages.dev](https://master.pgpvis.pages.dev/).

The latest commit in each PR is deployed at `pr-<number>.pgpvis.pages.dev`. For
example, for #13, the deployment can be accessed from
[pr-13.pgpvis.pages.dev](https://pr-13.pgpvis.pages.dev/).

Each commit also has its own preview deployment (as long as its checks have all
passed), but you will need to dig into GitHub Actions logs to find the links.

### Self-hosting prebuilt artifacts

You can download artifacts from
[Actions](https://github.com/shniubobo/pgpvis/actions) or
[Releases](https://github.com/shniubobo/pgpvis/releases), and serve them with
any HTTP server. For example:

```shell
tar xfz pgpvis-<version>.tar.gz
cd pgpvis-<version>
python -m http.server
```

### Building locally

If you don't feel like using the online version or the prebuilt artifacts of
`pgpvis`, you could build it locally.

First, you need a working [Node](https://nodejs.org/en/download) and
[Rust](https://rustup.rs/) installation.

Then, clone this repo, and do the following in the repo root:

```shell
rustup toolchain install
pnpm i
RUSTC_BOOTSTRAP=1 pnpm bootstrap
pnpm dist
```

To preview the built artifacts:

```shell
cd pgpvis-ui
pnpm preview
```

Follow the instructions you see in the terminal, which should show you a local
HTTP URL.

### Reproducible builds

If you want to build locally and get exactly the same artifacts that you can
download from Actions or Releases, you will need to follow some different steps.
In the repository root:

```shell
nvm use  # Use the pinned `node` version
rustup toolchain install  # Use the pinned Rust toolchain
pnpm i

RUSTFLAGS=-Dwarnings RUSTC_BOOTSTRAP=1 ./scripts/dist.sh
```

You will then find a `.tar.gz` file under the `dist` directory, which you can
self-host following steps in [Self-hosting prebuilt
artifacts](#self-hosting-prebuilt-artifacts).

To download OpenPGP signatures and verify them against the artifacts you have
built:

```shell
# Download from GitHub Releases, ...
wget https://github.com/shniubobo/pgpvis/releases/download/<version>/pgpvis-<version>.tar.gz.sig

# ... or download with `git`
git fetch <remote> refs/sigs/<version>:refs/sigs/<version>
git cat-file blob refs/sigs/<version> > ./dist/pgpvis-<version>.tar.gz.sig

# Retrieve the OpenPGP public key
# Using `base64` here to defend against email crawlers
gpg \
    --auto-key-locate wkd,local \
    --locate-keys \
    $(echo "bWVAc2huaXVib2JvLmNvbQo=" | base64 -d)

gpg --verify ./dist/pgpvis-<version>.tar.gz.sig
# You should see "Good signature" if everything has been correct
```

## Contributing

TODO: Add `CONTRIBUTING.md`.

In the meantime, please follow the building instructions above.

You may also have a look at the `package.json` files, which contain linting,
testing, and building commands. You can also find build scripts in the
[scripts](scripts) directory. Many code files in the [pgpvis-core](pgpvis-core)
and [pgpvis-ui](pgpvis-ui) subdirectories have detailed comments.

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
