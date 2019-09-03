==============
Writing parser
==============

In this section, we will describe basics on how to write your own parser using `pog`. It is assumed that you have already integrated `pog` into your project.
If not, see :ref:`installation`. If you already know how to write parser in `pog` and want to know about more advanced features, see :ref:`advanced`.

Principles
==========

Before you start reading this section, make sure that you are familiar with `grammars` in a sense of formal languages. Even though we have tried to write this documentation in a way
so that even person without extensive knowledge of formal languages will understand it, it is still expected that reader is somehow familiar with the concepts and at least is aware of them
and know what they represent.

When you want to parse something, you need to know the grammar of the language you are trying to parse out and that is also what `pog` expects from you. You need to give it a grammar
so it knows the syntax of what it is parsing. Every grammar is made out of rules. While parsing, these rules will be applied to the parts of the input you are parsing.
In `pog`, you will be able to specify so called `semantic actions` which are tied to the rules of your grammar. Each time some rule of your grammar will be applied,
its semantic action will be performed. That is where your code will come and it will give a meaning to the rules of your grammar. Your actions will however need some data to operate on.
Since rules are made out of symbols, there will be data tied the symbols of the right-hand side of the rule and you will be able to tie the result to the symbol on the left-hand side of the rule.

`pog` splits the process of parsing into two separate procedures in a similar way like `flex <https://github.com/westes/flex>`_ and `bison <https://github.com/akimd/bison>`_.
So at first, the input is tokenized into tokens using set of regular expressions. Some of the tokens can be simply skipped and never reach the parser at all (like whitespaces or comments)
but some may be turned into symbols of your grammar and represented in your grammar rules. This makes the grammar less cluttered. Since it is expected that you might want to perform actions
even when a token is found, you will be able to specify actions for tokens and tie some data to the symbol they represent.

The base class on which the whole `pog` stands is ``Parser<ValueT>``. ``ValueT`` here is data type that can be tied to `all` symbols of your grammar and when we say `all` we really mean it.
This data type will be tied to each symbol you have in your grammar and you will operate on it in your semantic actions. It will be also expected that each semantic actions will return value
of ``ValueT`` data type. The only constraints are that ``ValueT`` needs to be default constructible and copyable or movable (move is preferred if it is possible, if not then copy is performed).
We do now want to force you to use any specific data type but we recommend using ``std::variant``.

Tokenization
============

You start defining your parser with tokens. You need to provide regular expression that describes how the recognize the token on the input. The syntax for regular expression is Perl-like.
Here is an example on how to define tokens for recognizing boolean, integer literals and string literals (without escape sequences).

.. code-block:: cpp

  using Value = std::variant<int, bool, std::string>;
  pog::Parser<Value> parser;

  parser.token("\\s+");                   // Token for skipping whitespaces
  parser.token("=");                      // Token for single '='
  parser.token("(true|false)");           // Token for boolean value
  parser.token("[0-9]+");                 // Token for integer value
  parser.token(R"("[^"]*")");             // Token for string value (you might find raw string literals useful)
  parser.token("[a-zA-Z_][a-zA-Z0-9_]*"); // Token for identifiers

This will allow the parser to recognize what is on the input. If there is anything that it is not able to tokenize it is reported as syntax error. Tokenization also takes place only at the very
start of the input so there is no automatic skipping of unknown characters. Once the token is read, the characters that were matched with the regular expression are consumed and the new start
of the input starts at the end of the matched token.

There might be a situation when multiple regular expression match the same input. For example, consider regular expressions ``(true|false)`` and ``[a-zA-Z_][a-zA-Z0-9_]*``. They both would match on
``true`` or ``false`` but they would also match on ``trueaaa``. We certainly know that ``true`` and ``false`` should be tied to the first regular expression while ``trueaaa`` the second one but
tokenizer does not know that. To resolve these issues, tokenizer always prefers the longest possible match. If there are multiple matches of the same length then the token which is specified
earlier in the source code is chosen. There is also an another option to resolve this issue but it requires your interaction. If you specify token as ``fullword`` then the regular expression you
provide will be replaced by ``<YOUR_REGEXP>(\b|$)``. In our example, ``(true|false)`` would not match on ``trueaaa`` in that case.

.. code-block:: cpp

  parser.token("(true|false)").fullword();

By specifying these regular expressions, our input is now recognized but we should be able to specify what symbol in our grammar will these tokens represent. We do that with ``symbol`` method.

.. code-block:: cpp

  using Value = std::variant<int, bool, std::string>;
  pog::Parser<Value> parser;

  parser.token("\\s+");
  parser.token("=").symbol("=");
  parser.token("(true|false)").symbol("bool");
  parser.token("[0-9]+").symbol("int");
  parser.token(R"("[^"]*")").symbol("string");
  parser.token("[a-zA-Z_][a-zA-Z0-9_]*").symbol("id");

.. attention::

  Do not use symbol names prefix with either ``@`` or ``_``. Those are reseved for internal purposes of the parser. Proper working of the parser is not guaranteed in such case.

As you can see, we haven't specified any symbol for the first token since we are not interested in whitespaces in our grammar. This way, all whitespaces will be automatically skipped and we can
only focus on our 3 symbols which we have specified - ``bool``, ``int`` and ``string``. Once we have symbols, we would also like to take the actual boolean value, digits of a number or characters
of a string and tie it to our symbol. You specify the action with ``action`` method which expects callable object that accepts ``std::string_view`` containing the part of the input that was
matched with that specific regular expression and returns value of ``Value`` type.

.. code-block:: cpp

  using Value = std::variant<int, bool, std::string>;
  pog::Parser<Value> parser;

  parser.token("\\s+");
  parser.token("=").symbol("=");
  parser.token("(true|false)")
    .symbol("bool")
    .action([](std::string_view str) -> Value {
      return str == "true";
    });
  parser.token("[0-9]+")
    .symbol("int")
    .action([](std::string_view str) -> Value {
      return std::stoi(std::string{str});
    });
  parser.token(R"("[^"]*")")
    .symbol("string")
    .action([](std::string_view str) -> Value {
      return std::string{str.begin() + 1, str.end() - 1};
    });
  parser.token("[a-zA-Z_][a-zA-Z0-9_]*")
    .symbol("id")
    .action([](std::string_view str) -> Value {
      return std::string{str};
    });

Token for ``=`` does not need any action because it itself doesn't bear any value. We only need an information that it is located on the input.
You might also need to perform some action whenever end of an input is reached. In that case you can use ``end_token`` method.

.. code-block:: cpp

  parser.end_token().action([](std::string_view str) -> Value {
    // some action
    return {};
  });

Grammar rules
=============

Once your input is tokenized, you may start with specfying grammar rules. Let's define grammar rule for assignment of boolean, integer or string literal value to an variable.

.. code-block:: cpp

  // var_init -> id = literal
  parser.rule("var_init")
    .production("id", "=", "literal");
  // literal -> bool | int | string
  parser.rule("literal")
    .production("bool")
    .production("int")
    .production("string");

Se ``rule()`` method expects symbol on the left-hand side of the rule and can have multiple productions with multiple symbols on the right-hand side (even none). If we wanted to write rules for
languages which would represents 0 or more variable initializations, we could write that as (`ε` is usual way to denote empty string in formal languages):

.. code-block:: cpp

  // var_init_list -> var_init_list var_init | ε
  parser.rule("var_init_list")
    .production("var_init_list", "var_init")
    .production();

To specify action that should be performed when the rule is applied, you put it directly into the production at the very end.

.. code-block:: cpp

  // var_init -> id = literal
  parser.rule("var_init")
    .production("id", "=", "literal", (auto&& args) -> Value {
      // args[0] == value tied to 'id'
      // args[1] == value tied to '='
      // args[2] == value tied to 'literal'

      // Make sure that 'id' is declared
      // Assign args[2] to variable specified by args[0]
      return {};
    });
  // literal -> bool | int | string
  parser.rule("literal")
    .production("bool", [](auto&& args) -> Value { return std::move(args[0]); })
    .production("int", [](auto&& args) -> Value { return std::move(args[0]); })
    .production("string", [](auto&& args) -> Value { return std::move(args[0]); });

Action accepts ``std::vector<Value>`` as its parameters that contains values tied to the symbols of right-hand side of the rule. Returned value from the action is tied to the symbol on the
left-hand side of the rule.

Every grammar also needs to have some symbol which is used as a starting point for the whole parsing. That would be the symbol from which you are able to generate the whole language
you are able to parse. You need to specify this symbol explicitly using ``set_start_symbol()`` method.

.. code-block:: cpp

  parser.set_start_symbol("var_init");

Parsing
=======

Once you've specified all tokens and grammar rules, you are almost ready to start parsing. But before, you need to `prepare` your parser. This action will take your tokens and grammar rules
and will build parsing table. It will return report that will either mean success or some kind of problem with the grammar. To check the result, simply treat is as boolean value. You may also
iterate over it with range-based for loop to obtain issues found in the grammar. These issues can be:

* `Shift-reduce` conflict
* `Reduce-reduce` conflict

These conflicts are specific to shift-reduce parser which `pog` also generates. Those are types of parser which use stack to which they either shift values they see on the input or
they `reduce` the stack by popping out multiple values out of stack and shift another value (this represents application of a grammar rule). Whenever parser is not able to decide
whether to shift some value to the stack or to reduce using certain rule, it means `shift-reduce` conflict. If the parser is not able to decide whether to reduce by rule `A` or rule `B`, it is
`reduce-reduce` conflict. There isn't a simple cookbook on how to fix these conflicts in your grammar (and sometimes it is not even possible) so if you run into one, you might want to learn
more about parsers and how these conflicts occur to resolve them. The fact that these issues are in your grammar does not mean that you cannot use your parser. You may still be able to parse out
your language but you might not be able to parse certain constructs of your language and will receive syntax errors. There are however cases in which these conflicts can be completely ignored.

After preparing your parser, you are ready to parse the input using method ``parse()``. It accepts input stream (such as ``std::istream``) and returns ``std::optional<ValueT>``. In case of
a successful parsing, the returned value will contain what was tied to the starting symbol of the grammar. When syntax error occurrs, ``parse()`` raises an exception of type ``SyntaxError``.
In some corner cases which are not covered by syntax errors but might represent internal failure of the parser, the returned optional value will be empty.

.. code-block:: cpp

  auto report = parser.prepare();
  if (!report)
  {
    for (const auto& issue : report)
      std::cerr << issue.to_string() << std::endl;
  }

  std::stringstream input(/* your input */);
  try
  {
    auto result = parser.parse(input);
    if (!result)
    {
      std::cerr << "Error" << std::endl;
      return;
    }

    std::cout << "Parsed value " << result.value() << std::endl;
  }
  catch (const SyntaxError& err)
  {
    std::cerr << err.what() << std::endl;
  }

Examples
========

Check `examples <https://github.com/metthal/pog/tree/master/examples>`_ folder to see some simple examples of existing parsers.
