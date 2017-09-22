# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2017-09-21

### Added
- This CHANGELOG file
- `SshKeyPair`: added typehints
- `SshPrivateKey`: added `getPublicKey` Method
- `SshPublicKey`: added `fromPrivateKey()` Method
- `SshPublicKey`: added `setComment()` Method
- `SshKey`: added `getSize()`
- added Putty Key Format
- added linux line ending 
### Changed
- `SshKey`: `getKeyData()` has now `openssh` as default format 
- `SshKey`: `getKeyData()` return normalized line endings (linux)
- [BC Break] `SshKeyPair`: changed constructor signature, switched public with private to allow to `null` as public key
- `SshKeyPair`: increased default bit size to 4096
- `SshPublicKey`: `constructor` to allow to set the comment & added typehints
