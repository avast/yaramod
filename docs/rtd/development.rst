===========
Development
===========


Architecture
============

Yaramod is a C++ library with Python bindings capable of parsing, building, formatting and also modifying YARA rules; hence the main four parts of Yaramod are:

Parser of YARA rules
    The main parser class is the ``ParserDriver`` class declared in the `header file <https://github.com/avast/yaramod/blob/master/include/yaramod/parser/parser_driver.h>`_ ``parser_driver.h``
    and defined in `file <https://github.com/avast/yaramod/blob/master/src/parser/parser_driver.cpp>`_ ``parser_driver.cpp``.
    The parser is based on `POG <https://github.com/metthal/pog>`_ and its grammar and tokens are defined in methods ``defineTokens``
    and ``defineGrammar`` of the ``ParserDriver`` class. Detailed wiki page on how to use yaramod to parse YARA rules can be found `here <https://github.com/avast/yaramod/wiki/Parsing-YARA-files>`_ .

Builder of YARA rules
    The builder machinery is declared within the `builder folder <https://github.com/avast/yaramod/tree/master/include/yaramod/builder>`_.
    The ``YaraExpressionBuilder`` creates expressions so that YARA rules conditions can be created. The ``YaraHexStringBuilder`` is a tool
    for easy creation of hexadecimal strings. The ``YaraRuleBuilder`` helps to create YARA rules and the ``YaraFileBuilder`` is there
    to construct YARA files from rules and module imports. More on the construction of YARA files is written `here <https://github.com/avast/yaramod/wiki/Constructing-YARA-files>`_.

YARA rules formatting
    The main component taking care of proper formatting of YARA files is the ``TokenStream`` defined in `file <https://github.com/avast/yaramod/blob/master/include/yaramod/types/token_stream.h>`_ ``tokenstream.h``.
    Each ``YaraFile`` instance holds a ``TokenStream`` instance in which all Tokens that the ``YaraFile`` refers to are stored.
    The ``TokenStream::getText`` method prints the tokens formatted in the desired format. The ``YaraFile::getTextFormatted`` method
    simply calls the ``getText`` method of the TokenStream that it owns.
    Please see wiki `page <https://yaramod.readthedocs.io/en/latest/formatting_rulesets.html>`_ for more on formatting.

YARA rules modifying visitor
    The class ``ModifyingVisitor`` is defined in `modifying_visitor.h` and serves as the base class for our custom visitors designed
    to modify specific parts of visited conditions. See section `Modifying Rulesets <https://yaramod.readthedocs.io/en/latest/modifying_rulesets.html>`_ for more information and examples.

Run it locally
==============
See `Installation <https://yaramod.readthedocs.io/en/latest/installation.html>`_ section.