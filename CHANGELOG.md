# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.77.4](https://github.com/contentauth/c2pa-cbor/compare/v0.77.3...v0.77.4)
_04 September 2026_

### Fixed

* Preserve CBOR tags on Value round-trip ([#29](https://github.com/contentauth/c2pa-cbor/pull/29))

## [0.77.3](https://github.com/contentauth/c2pa-cbor/compare/v0.77.2...v0.77.3)
_02 September 2026_

### Fixed

* Update encoder and decoder to handle that it is not human readable ([#26](https://github.com/contentauth/c2pa-cbor/pull/26))

### Other

* Fixes #22 Option<f32>/Option<f64> deserialization for CBOR floats ([#25](https://github.com/contentauth/c2pa-cbor/pull/25))

## [0.77.2](https://github.com/contentauth/c2pa-cbor/compare/v0.77.1...v0.77.2)
_31 January 2026_

### Added

* Ensure tagged types are encoded and decoded as tagged ([#10](https://github.com/contentauth/c2pa-cbor/pull/10))

## [0.77.1](https://github.com/contentauth/c2pa-cbor/compare/v0.77.0...v0.77.1)
_30 January 2026_

### Fixed

* Serialize newtype structs transparently ([#7](https://github.com/contentauth/c2pa-cbor/pull/7))

## [0.77.0](https://github.com/contentauth/c2pa-cbor/releases/tag/v0.77.0)
_22 January 2026_

* Initial public release

(NOTE: The version number starts here because a previous version was inadvertently published from the c2pa-rs project using its version number. These projects, though related, are not meant to be versioned together.)
