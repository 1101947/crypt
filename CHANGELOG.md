# Changelog

All notable changes to this project will be documented here.

To see more information about this file, see README.md section CHANGELOG file

This project is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and does not use semantic versioning.

## [Unreleased]
## [Current]
### Changed
- README.md : rewrote and removed some sections
- renamed module name from crypt to github.com/1101947/crypt to be able to use with standard go package utils.
### Removed
- main.go


## [v2026-07-25_15-45-51Z__1d4f26c1d1fcb3d455f29f3a667cf9de4cd32475]
### Changed
- cmdrouter API(function calls from cmdrouter lib). Added Cmd type that implements Exec() error method, now Handler.Process() method doesn't run commands code itself, but returns Cmd type that allows delayed execution after all the neccessary preparations(parsing files, geting envvars).
### Added
- new TODO entries in README.md
## [v2026-07-24_13-33-58Z__553300ad1bd3859527cfc05c2c49422238c3fe33]
### Added
- Tests for cryptafile
- Entry in TODO list in README.md
## [v2026-07-22_21-00-06Z__65c57e08f1244bcc355702afccb22534fa3d883b]
### Added
- New TODO entries in README.md
### Fixed
- Some things in Changelog section in README.md
## [v2026-07-22_19-59-25Z__af165cf99aad5392377bb76d71d406b2bf9a75eb]
### Added
- new section "Versioning" in README.md
## [v2026-07-22_19-20-40Z__65d0b8da6f4e767ffdfaefa3a7f79e5b9665db77]
### Fixed
- cleaned README.md up
- updated run.txt
## [v2026-07-22_16-20-43Z__100cf2e0284c25e0c9a7c6433ee516409514ad63]
### Added
- file CHANGELOG.md
- section Changelog in README.md 

