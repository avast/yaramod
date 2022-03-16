# Changelog

# v3.12.5 (2022-03-16)

* Add comment_behind and comment_before_token to Expression builder ([#195](https://github.com/avast/yaramod/issues/195), [#194](https://github.com/avast/yaramod/pull/194))
* Introduce on-line commenting of con/disjunctions ([#195](https://github.com/avast/yaramod/issues/195), [#194](https://github.com/avast/yaramod/pull/194))

# v3.12.3 (2022-02-18)

* Add `dex.has_method` and `dex.has_class` ([#157](https://github.com/avast/yaramod/issues/157), [#201](https://github.com/avast/yaramod/pull/201))
* Add `math.to_number`, `math.abs`, `math.count`, `math.percentage` and `math.mode` functions ([#157](https://github.com/avast/yaramod/issues/157), [#199](https://github.com/avast/yaramod/pull/199))
* Add operator `in` ([#157](https://github.com/avast/yaramod/issues/157), [#204](https://github.com/avast/yaramod/pull/204))
* Add `pe.import_details` and `pe.delayed_import_details` ([#157](https://github.com/avast/yaramod/issues/157), [#200](https://github.com/avast/yaramod/pull/200))
* Add support for % numeric literal in `of` expressions ([#157](https://github.com/avast/yaramod/issues/157), [#198](https://github.com/avast/yaramod/pull/198))
* Add support for `none` keyword ([#157](https://github.com/avast/yaramod/issues/157), [#203](https://github.com/avast/yaramod/pull/203))
* Add `pe.entry_point_raw` ([#157](https://github.com/avast/yaramod/issues/157), [#200](https://github.com/avast/yaramod/pull/200))
* Update YARA_SYNTAX_VERSION in docs to 4.2

# v3.12.2 (2022-01-31)

* Added support for `dynsym_entries` and `dynsym` ELF module attributes ([#196](https://github.com/avast/yaramod/pull/196))
* Added support for `algorithm_oid` from PE module ([#197](https://github.com/avast/yaramod/pull/197))

# v3.12.1 (2021-12-02)

* Make empty strings section invalid ([#141](https://github.com/avast/yaramod/issues/141), [#192](https://github.com/avast/yaramod/pull/192))
* Fix escaped character handling in regex ([#186](https://github.com/avast/yaramod/issues/186), [#191](https://github.com/avast/yaramod/pull/191))

# v3.12.0 (2021-11-26)

* Dropped support for Python 3.7 and added support for Python 3.10 ([#190](https://github.com/avast/yaramod/pull/190))

# v3.11.1 (2021-11-23)

* Strip trailing whitespace off oneline comments ([#149](https://github.com/avast/yaramod/issues/149), [#189](https://github.com/avast/yaramod/pull/189))
* Fix adding meta to add it after comment of last present meta if present ([#102](https://github.com/avast/yaramod/issues/102), [#188](https://github.com/avast/yaramod/pull/188))
* Separate includes and imports with blank lines ([#187](https://github.com/avast/yaramod/pull/187), [#130](https://github.com/avast/yaramod/issues/130))

# v3.11.0 (2021-08-30)

* Added additional constants of enums to `pe` module ([#183](https://github.com/avast/yaramod/pull/183))
* Added support for `iequals` operator ([#182](https://github.com/avast/yaramod/pull/182))
* Make `strings` and `variables` sections interchangable ([#184](https://github.com/avast/yaramod/pull/184))
* Added missing `dotnet` module ([#185](https://github.com/avast/yaramod/pull/185))

# v3.10.8 (2021-07-28)

* Add Python binding for `yaramod::IntFunctionEndianness` ([#132](https://github.com/avast/yaramod/issues/132), [#181](https://github.com/avast/yaramod/pull/181)).
* Add unary operator `defined` ([#178](https://github.com/avast/yaramod/pull/178)).
* Fix generation of double values - always use decimal notation ([#179](https://github.com/avast/yaramod/pull/179)).
* Fix typos in documentation ([#180](https://github.com/avast/yaramod/pull/180)).

# v3.10.7 (2021-06-16)

* Avoid global symbols to be renamed when renaming local variable  ([#174](https://github.com/avast/yaramod/pull/174))

# v3.10.6 (2021-06-09)

* Fix for multi-line arrays to be formatted with proper indentation ([#172](https://github.com/avast/yaramod/pull/172), [#171](https://github.com/avast/yaramod/issues/171))
* Added pe.version_info_list and pe.number_of_version_infos ([#167](https://github.com/avast/yaramod/pull/167))

# v3.10.5 (2021-06-03)

* Fixed YaraFileBuilder::get with recheck to use the builder's module pool ([#166](https://github.com/avast/yaramod/pull/166))

# v3.10.4 (2021-05-27)

* Travis: Add brew upgrade step ([#164](https://github.com/avast/yaramod/pull/164))
* Add missing REFERENCE_SYMBOL, LSQB_ENUMERATION, RSQB_ENUMERATION Pytnoh bindings ([#160](https://github.com/avast/yaramod/pull/160))
* Incomplete rules parsing allowing also unknown symbols and imports ([#159](https://github.com/avast/yaramod/pull/159), [#45](https://github.com/avast/yaramod/issues/45), [#97](https://github.com/avast/yaramod/issues/97))
* Fixed pe.rich_signature.raw_data and pe.rich_signature.clear_data types to string.

# v3.10.3 (2021-05-14)

* Feature for older compilers: Include filesystem library based on its availability.

# v3.10.2 (2021-04-28)

* Fixed previous release by adding cmake foulder in MANIFEST.sh.

# v3.10.1 (2021-04-28)

* Fixed issues with older compilers not providing symbols for std::filesystem function ([#156](https://github.com/avast/yaramod/pull/156))

# v3.10.0 (2021-04-23)

* Removed private Avast symbols - modules are dynamically loaded from JSON ([#143](https://github.com/avast/yaramod/pull/143), [#13](https://github.com/avast/yaramod/issues/13), [#98](https://github.com/avast/yaramod/issues/98))

# v3.9.2 (2021-06-04)

* Hotfix for user-defined arrays to be handled correctly by autoformatter ([#170](https://github.com/avast/yaramod/pull/170), [#171](https://github.com/avast/yaramod/issues/171))
* Allow hotfix branches to be built in Travis and Appveyor ([#170](https://github.com/avast/yaramod/pull/170))

# v3.9.1 (2021-03-29)

* Exposed token from `Meta` objects ([#155](https://github.com/avast/yaramod/pull/155))
* Fixed documentation in parsing_rulesets.rst ([#153](https://github.com/avast/yaramod/pull/153))

# v3.9.0 (2021-01-20)

* Turned `ImportFeatures` into `Features` because it now affects more than just imported modules ([#148](https://github.com/avast/yaramod/pull/148))
* Added support for `of` expression with user-defined arrays ([#148](https://github.com/avast/yaramod/pull/148))
* Added support for user-defined variables inside rules scope ([#148](https://github.com/avast/yaramod/pull/148))

# v3.8.1 (2020-12-10)

* Added building of Python wheel for Windows using Python 3.9

# v3.8.0 (2020-10-04)

* Yara 4.0 features as Base64 string modifier, for loop over dictionary and more ([#144](https://github.com/avast/yaramod/pull/144))

# v3.7.5 (2020-09-13)

* Added new VirusTotal AV external variables

# v3.7.4 (2020-08-25)

* Converted `TokenType` enum to c++11 enum class ([#123](https://github.com/avast/yaramod/pull/123))
* Fixed include directive not to extract tokens ([#129](https://github.com/avast/yaramod/pull/129))

# v3.7.3 (2020-08-18)

* Fixed token location computing of plain and hex strings ([#124](https://github.com/avast/yaramod/pull/124))
* Exposed token and symbol file position via python bindings ([#120](https://github.com/avast/yaramod/pull/120))
* Fixed both python and c++ bool Simplifiers ([#121](https://github.com/avast/yaramod/pull/121))
* Renamed `ModifyingVisitor::cleanUpTokenStreams` to `ModifyingVisitor::cleanup_tokenstreams` ([#121](https://github.com/avast/yaramod/pull/121))
* Unified duplicated `location.h` headers ([#118](https://github.com/avast/yaramod/pull/118))

# v3.7.2

* Return to the root directory before deploying stage in Travis build so the deploy to pypi is succesful

# v3.7.1

# v3.7.0 (2020-07-24)

* Added function for suricata matching ([#115](https://github.com/avast/yaramod/pull/115))
* Added support for classes and windows matching in the cuckoo module ([#113](https://github.com/avast/yaramod/pull/113))
* Modifiers of rules can be altered with `Rule::setModifier`. ([#110](https://github.com/avast/yaramod/pull/110), [#114](https://github.com/avast/yaramod/pull/114))
* Tokens of expressions changed by modifying visitors are altered appropriately. ([#100](https://github.com/avast/yaramod/pull/100), ([#111](https://github.com/avast/yaramod/pull/111)), [#75](https://github.com/avast/yaramod/issues/75))
* The documentation is built in Travis to check its correctness.
* Improve links between individual constructs in internal representation. ([#96](https://github.com/avast/yaramod/pull/96), [#73](https://github.com/avast/yaramod/issues/73))

# v3.6.0 (2020-04-20)

* Added new `elf` module function `elf.symtab_symbol()` ([#94](https://github.com/avast/yaramod/pull/94))
* Added new overloads of `androguard.signature.hits()` function

# v3.5.0 (2020-03-26)

* Added `metadata` module ([#90](https://github.com/avast/yaramod/pull/90))

# v3.4.1 (2020-03-25)

* Fix and/or conjunction auto-formatting: comment/newline tokens before it are moved behind it. ([#89](https://github.com/avast/yaramod/pull/89))

# v3.4.0 (2020-03-25)

* In autoformatting, new lines before and/or are removed. ([#79](https://github.com/avast/yaramod/issues/79), [#86](https://github.com/avast/yaramod/pull/86))
* In autoformatting, unwanted multiple blank lines are made single new line. ([#77](https://github.com/avast/yaramod/pull/77))
* CXX flags are propagated to POG's dependencies. ([#82](https://github.com/avast/yaramod/pull/82), [#87](https://github.com/avast/yaramod/pull/87))
* In autoformatting, comments are aligned together with the corresponding lines. ([#81](https://github.com/avast/yaramod/pull/81))
* files are loaded as binary which prevents wrong line endings on Windows. ([#80](https://github.com/avast/yaramod/pull/80))
* `YaraFileBuilder` sorts imports lexicographically and avoids duplicities. ([#78](https://github.com/avast/yaramod/pull/78))

# v3.3.7 (2020-03-11)

* Unified integral types in `Literal` class ([#71](https://github.com/avast/yaramod/issues/71))
* Added Python bindings for `Literal` class ([#72](https://github.com/avast/yaramod/issues/72))

# v3.3.6 (2020-02-26)

* Fixed regression introduced in previous version by breaking parsing of `[` and `]` ([#70](https://github.com/avast/yaramod/pull/70))

# v3.3.5 (2020-02-25)

* Fixed issues with parsing `[` and `]` inside regular expressions classes enclosed in `[` and `]` ([#69](https://github.com/avast/yaramod/pull/69), [#67](https://github.com/avast/yaramod/issues/67))
* Installation through `pip` now properly fails if CMake is not found ([#64](https://github.com/avast/yaramod/issues/64))

# v3.3.4 (2020-02-06)

* Yaramod can now be reused without crashing after if raised error because of failed parsing ([#66](https://github.com/avast/yaramod/pull/66), [#65](https://github.com/avast/yaramod/issues/65))

# v3.3.3 (2020-02-05)

* Added support for loading deprecated module functions ([#62](https://github.com/avast/yaramod/issues/62), [#63](https://github.com/avast/yaramod/pull/63))

# v3.3.2 (2020-01-30)

* Fixed bug which prevented creating rule with empty string meta from builder ([#58](https://github.com/avast/yaramod/issues/58), [#59](https://github.com/avast/yaramod/pull/59)).

# v3.3.1 (2020-01-23)

* Fixed segfault in case of syntax error which was caused by unexpected end of file

# v3.3.0 (2020-01-23)

* Builders now work properly when you create `YaraExpressionBuilder` out of already existing expression.
* Calculation of rule locations now works again.
* Include files are now closed as soon as possible to not exhaust file descriptors.
* Very last rule in the parsed file is now reported to be located in the correct file.
* Include guarded parsing mode now works properly again.

# v3.2.0 (2020-01-21)

* Added Python bindings for `ImportFeatures`
* Import features are now specified when creating `Yaramod` instance

# v3.1.0 (2020-01-17)

* Target `install` is now properly installing yaramod again.
* Added support for language YARA features added in 3.11.0 ([#51](https://github.com/avast/yaramod/pull/51), [#52](https://github.com/avast/yaramod/pull/52)).
* Autoformatting now automatically adds new lines where needed ([#53](https://github.com/avast/yaramod/pull/53)).

# v3.0.1 (2019-12-19)

* Make autoformatting use LF or CRLF depending on what is used in the file ([#48](https://github.com/avast/yaramod/issues/48)).
* Added missing getter IdExpression::getSymbol().

# v3.0.0 (2019-12-13)

* Replaced `flex` and `bison` with `pog`.
* Added autoformatting of YARA rules.
* Added `cuckoo.process.scheduled_task()`.

# v2.12.1 (2019-10-29)

* Re-release of v2.12.0 because it was broken on git

# v2.12.0 (2019-10-25)

* Enhancement: Bump the required C++ standard from 14 to 17.
* Enhancement: Replace uses of `nonstd::optional` from `dep/optional_lite` with standard C++17 `std::optional`. Remove the `optional_lite` dependency.
* Enhancement: Replace uses of `mpark::variant` from `dep/variant` with standard C++17 `std::variant`. Remove the `variant` dependency.

# v2.11.0 (2019-10-04)

* New: Added `cuckoo.process.modified_clipboard()`, `cuckoo.network.connection_ip()`, `cuckoo.network.connection_country()` and `cuckoo.network.irc_command()`.
* New: Module `phish`.

# v2.10.0 (2019-09-18)

* New: Added `cuckoo.process.api_call()`

# v2.9.0 (2019-08-19)

* New: Interface for obtaining internal representation of regular expressions ([#29](https://github.com/avast/yaramod/issues/29)).
* New: Interface for visitor over regular expressions ([#33](https://github.com/avast/yaramod/pull/33)).

# v2.8.0 (2019-05-16)

* New: Added support for `pe.iconhash()` function.

# v2.7.0 (2019-04-30)

* New: Methods for manipulation of rule name and tags ([#27](https://github.com/avast/yaramod/issues/27)).
* Fix: Support for anonymous string has been fixed ([#26](https://github.com/avast/yaramod/issues/26)).

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
