# yaramod

[![Documentation Status](https://readthedocs.org/projects/yaramod/badge/?version=latest)](https://yaramod.readthedocs.io/en/latest/?badge=latest)

> :warning: Since version 4.x.x, yaramod is now focused on keeping compatibility with [YARA-X](https://github.com/VirusTotal/yara-x) and may not parse all YARA compatible rules anymore. It is planned to eventually decommission whole yaramod project in favor of YARA-X native parser. If you are interested in just YARA compatibility then still use yaramod 3.x.x. :warning:

`yaramod` is a library that provides parsing of [YARA](https://github.com/VirusTotal/yara) rules into AST and a C++ programming interface to build new YARA rulesets. This project is not associated with the YARA project.

`yaramod` also comes with Python bindings and this repository should be fully compatible with installation using `pip`.

## User Documentation

You can find our documentation on [Read the Docs](https://yaramod.readthedocs.io/en/latest/).

## API Documentation

You can generate the API documentation by yourself. Pass `-DYARAMOD_DOCS=ON` to `cmake` and run `make doc`.

## License

Copyright (c) 2017 Avast Software, licensed under the MIT license. See the `LICENSE` file for more details.

`yaramod` uses third-party libraries or other resources listed, along with their licenses, in the `LICENSE-THIRD-PARTY` file.

## Contributing

See [RetDec contribution guidelines](https://github.com/avast/retdec/wiki/Contribution-Guidelines).
