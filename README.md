# yaramod

`yaramod` is a library that provides parsing of [YARA](https://github.com/VirusTotal/yara) rules into AST and a C++ programming interface to build new YARA rulesets. This project is not associated with the YARA project.

## Usage Example

See the [wiki](https://github.com/avast-tl/yaramod/wiki).

## Requirements

* C++ compiler with C++14 support
* CMake (version >= 3.6)

## Build and Installation

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=<Debug|Release> [OPTIONS ...] ..
```

Available options are:

* `YARAMOD_DOC` - provide build target `doc` for building documentation with Doxygen. (Default: OFF)
* `YARAMOD_TESTS` - build unit tests. (Default: OFF)

## API Documentation

You can generate the API documentation by yourself. Pass `-DYARAMOD_DOC=ON` to `cmake` and run `make doc`.

## License

Copyright (c) 2017 Avast Software, licensed under the MIT license. See the `LICENSE` file for more details.

`yaramod` uses third-party libraries or other resources listed, along with their licenses, in the `LICENSE-THIRD-PARTY` file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast-tl/retdec/wiki/Contribution-Guidelines).
