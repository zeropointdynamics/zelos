# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Version 0.2.0] - 2020-08-04

### Added

- Plugins: Yarascan
- Introduction of Zelos Manipulation Language (ZML), used for specifying events on the command line and in scripts. New zml_hook function in api
- Ability to redirect input to stdin
- Hooks for internal memory reads, writes, and maps
- Linked to crashd plugin, containing separate plugins for heap memory guards, static analysis via IDA Pro, and dataflow using QEMU TCG

### Changed

- Moved to different command line flags for specifying what degree of information (instructions or syscalls) is printed while running
- Better support for lists in command line arguments
- Flags can be passed to the emulated program via the command line
- Misc. bug fixes (thanks to seth1002)
- General improvements to syscalls

### Removed

- Verbosity command line flag (now handled via other flags)

## [Version 0.1.0] - 2020-05-29

### Added

- Plugins: IDA overlays, remote debug server
- Additional plugin APIs

### Changed

- Minor syscall emulation improvements
- Memory management overhaul

### Removed

- N/A

## [Version 0.0.1] - 2020-03-03

### Added

- N/A

### Changed

- Updated documentation

### Removed

- N/A

## [Version 0.0.0] - 2020-03-02

Initial public release.

### Added

- Initial open source commit.

### Changed

- N/A

### Removed

- N/A

[0.0.0]: https://github.com/zeropointdynamics/zelos/releases/tag/v0.0.0
