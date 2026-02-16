# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fixed version parsing to support alphanumeric patch versions (e.g., `1.1.0_dev2`, `1.1.0dev`)

### Added

- Support for new Cuvex BIT card format with PBKDF2 key derivation
- Support for delimiter-based NDEF card format (02413A, 02433A, 02493A, 024D3A)
- Automatic format detection between legacy fixed-length and new delimiter-based cards
- PBKDF2 key derivation
- Biometry detection and validation (BIT0/BIT1 markers)

### Changed

- Refactored `process_card()` to support both legacy and new card formats
- Updated card extraction logic to use delimiters for new format and fixed lengths for legacy

### Removed

## [1.1.1] - 2024-11-05

### Removed

- Mac OSX binaries

## [1.1.0] - 2024-11-04

### Added

- Read binary files exported by Cuvex app.
- Decrypt monosign and multising NFC cards
- Process of plain text from decrypted cards created with Cuvex device
- Process of plain text from decrypted cards created with Cuvex app
- Process of BIP39 seed phrases from decrypted cards created with Cuvex device
- Process of BIP39 seed phrases from decrypted cards created with Cuvex App
- Process of SLIP39 seed phrases from decrypted card
- Process of Monero seed phrases from decrypted card
- User interface to read and decrypt NFC cards






