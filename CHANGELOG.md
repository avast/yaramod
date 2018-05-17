# Changelog

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
