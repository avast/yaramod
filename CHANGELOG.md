# Changelog

# v2.6.0 (2019-04-30)

* New: Class `Rule` now has interface for direct manipulation with meta of the rules.

# v2.5.0 (2019-04-21)

* New: Expression builder now contains `doubleVal` for building double expressions ([#22](https://github.com/avast/yaramod/issues/22)).
* Fix: Compilation now works in Cygwin environment ([#25](https://github.com/avast/yaramod/issues/25)).

# v2.4.2 (2019-04-02)

* Fix: `pe.data_directories` is now correctly an array and not a structure.

# v2.4.0 (2019-02-27)

* Enhancement: Python interface of `String.pure_text` now returns `bytes` instead of `str` to prevent unicode decoding errors with strings containg invalid UTF-8 sequences.

# v2.3.0 (2019-02-01)

* New: Added modules `androguard`, `dex`, `macho`, `time` and new fields in `pe` module ([#14](https://github.com/avast/yaramod/issues/14)).
* New: Added new functions to `cuckoo` module related to matching Android executable files.
* New: Added support for `xor` string modifier ([#14](https://github.com/avast/yaramod/issues/14)).
* New: Added constants `YARAMOD_VERSION_MAJOR`, `YARAMOD_VERSION_MINOR`, `YARAMOD_VERSION_PATCH` and `YARAMOD_VERSION` which contain the version of the yaramod.
* New: Added constant `YARA_SYNTAX_VERSION` which contains the version of YARA from which `yaramod` is based of.
* New: Symbols reported in parser errors now have human friendly aliases instead of enum names.
* Fix: Multiline hex strings are now correctly parsed ([#10](https://github.com/avast/yaramod/issues/10)).
* Fix: Unexpected character after import statement now raises an error ([#16](https://github.com/avast/yaramod/issues/16)).

# v2.2.2 (2018-11-09)

* Fix: Build with bison 3.2 ([#11](https://github.com/avast/yaramod/issues/11)).
* Enhancement: Updated optional-lite dependency to the newest version.

# v2.2.1 (2018-10-03)

* Fix: Fixed build on certain specific MSVC versions.

# v2.2.0 (2018-07-30)

* New: Added method for removing meta information from the rules.

# v2.1.2 (2018-05-17)

* New: Added install target to build system.
* New: Added new cuckoo module functions.

# v2.1.1 (2018-04-20)

* Fix: Fixed problem with too many open files on Windows when includes are used.

# v2.1.0 (2018-03-26)

* Enhancement: Unknown escape sequences in plain strings are now considered as parser errors.
* Fix: Integer-based for-loops now won't raise the `'Redefinition of variable ...'` error if they are independent of each other (#3).
* Fix: Plain strings now only allow escape sequences `\n`, `\t`, `\\`, `\"` and `\xYZ`.
* Fix: TAB now counts only as a single character when reporting errors.

# v2.0.1 (2018-03-15)

* Fix: `ModifyingVisitor` now won't delete string offset or length expression without array subscript on its own.

# v2.0.0 (2018-03-14)

* New: Python bindings were added to the `yaramod` library.
* Enhancement: Parsed rules now contain information about the file they are located in and the line number.
* Fix: Line numbers of errors are now reported correctly for files with includes.

# v1.0.1 (2018-01-18)

* Enhancement: Syntax errors not throw exceptions instead of just returning empty file.
* Enhancement: Removed submodule dependencies.

# v1.0 (2017-12-12)

Initial release.
