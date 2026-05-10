# Contributing to Signet

Thank you for your interest in contributing to Signet.

## Contributor License Agreement

Before your contribution can be accepted, you must sign the **North9 Contributor License Agreement (CLA)**. The CLA grants North9 LLC the right to include your contribution in both the open-source (AGPL v3) and commercial releases of Signet, including commercial SDK licenses sold to camera app developers and government agencies.

The CLA is managed automatically via [CLA Assistant](https://cla-assistant.io/). When you open a pull request, a bot will check your CLA status and prompt you to sign if you haven't already.

## Development

Requires Rust 1.75+.

```sh
git clone https://github.com/North9LLC/Signet
cd Signet
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## Guidelines

- Zero clippy warnings (`-D warnings`) required before merge
- Cryptographic changes (watermark format, FEC parameters, drand verification) require discussion in an issue before implementation — these affect wire compatibility
- Changes to the C FFI (`src/lib.rs`, `include/signet.h`) require updating the header file and both SDK wrappers (`sdk/ios/`, `sdk/android/`)
- Add tests for any changes to `src/imgwm.rs`, `src/fec.rs`, or `src/crypto.rs`

## Wire format stability

The 96-byte frame format is fixed. Any proposal to change it must be versioned and backward-compatible. Breaking changes require a new major version with a new frame magic number.

## Security

For security vulnerabilities, open a [private advisory](https://github.com/North9LLC/Signet/security/advisories/new) — not a public issue.

## License

By contributing, you agree that your contributions will be licensed under both AGPL v3 and North9's commercial license per the CLA.
