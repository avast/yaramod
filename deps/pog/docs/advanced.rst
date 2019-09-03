.. _advanced:

=================
Advanced features
=================

Operator & rule precedence
==========================

Typical features of many languages are operators such as arithmetic operators, bitwise operators, relational operators and many others. These operators have certain precedence and associativity.
That also complicates parsing process because if we for example take ``2 + 3 * 4 - 5``, the order of evaluation is important here. The usual way to model this in grammars is to specify all of this
directly in grammar rules but this might seriously complicate the whole grammar. This is a grammar you would usually write for addition and multiplication expressions with support for parentheses.

.. math::

  E & → E + E \\
  E & → E * E \\
  E & → ( E ) \\
  E & → number

This doesn't however incorporate any precedence whatsoever. Here is a grammar with resolved precedences.

.. math::

  E & → E + T \\
  E & → T \\
  T & → T * F \\
  T & → F \\
  F & → ( E ) \\
  F & → number

Now imagine this situation with much more operators and much more precedence levels. `pog` shifts the responsibility of handling precedences from the user to itself. At first, you need to define
precedence level and associativity of the token you consider as operators.

.. code-block:: cpp

  parser.token("\\+").symbol("+").precedence(1, Associativity::Left);
  parser.token("-").symbol("-").precedence(1, Associativity::Left);
  parser.token("\\*").symbol("*").precedence(2, Associativity::Left);
  parser.token("/").symbol("/").precedence(2, Associativity::Left);

Level of the precedence is just an unsigned integer. The higher the number, the greater the precedence. If two operators have the same precedence then associativity comes in to resolve this situation.
During parsing, precedence is resolved at the moment of operator symbol being the next token on the input. To resolve which symbol to compare against, the right-most terminal symbol of the rule
which would be currently reduced is considered as operator.

Let's imagine it on an example. You are currently in the state of the parser where you are deciding whether to reduce by rule :math:`E → E + E` or shift the following symbol.
The next symbol on the input is :math:`*`. Right-most terminal in :math:`E + E` is :math:`+` so we should rather shift than reduce because multiplication needs to be evaluated before addition.

Precedence cannot only be assigned to tokens (or more presicely symbols tied to tokens) but also rules. If the rule has priority assigned then this priority is considered rather than
priority of the right-most terminal. The case when this can be useful is for example for unary minus. Unary minus uses the same symbol as subtraction but unary minus has greater precedence than
for example multiplication or division.

.. code-block:: cpp

  parser.token("\\+").symbol("+").precedence(1, Associativity::Left);
  parser.token("-").symbol("-").precedence(1, Associativity::Left);
  parser.token("\\*").symbol("*").precedence(2, Associativity::Left);
  parser.token("/").symbol("/").precedence(2, Associativity::Left);
  parser.token("[0-9]+").symbol("number").action(/* action */);

  parser.rule("E")
    .production("E", "+", "E")
    .production("E", "-", "E")
    .production("E", "*", "E")
    .production("E", "/", "E")
    .production("-", "E")
      .precedence(3, Associativity::Right)
    .production("number");

Whenever you specify precedence like this, it is always tied to the last production you have specified.

Mid-rule actions
================

Most of the times, it is enough to have a rule action being preformed after the whole rule is applied (or rather `reduced` since we are in advanced section). There might be some cases when
there is a need for so called `mid-rule action`. That is action performed after only certain part of the rule has been parsed out. This comes as a problematic since the parser cannot know
whether it is in the middle of parsing certain rule. It will know which rule to reduce after it has parsed its whole right-hand side (and also depending on the next input symbol).

`pog` tries to solve this by internally splitting your rule into more smaller rules to achieve this. Let's take for example rule ``func -> function id ( args ) { body }``. Usually you would
write it as:

.. code-block:: cpp

  parser.rule("func")
    .production("function", "id", "(", "args", ")", "{", "body", "}",
        [](auto&& args) { /* action */ }
    );

But you might want to check whether name of the function does not collide with some other already defined function before you start parsing the function body to exit early. You can write it as following:

.. code-block:: cpp

  parser.rule("func")
    .production(
        "function", "id",
            [](auto&& args) { /* action 1 */ },
        "(", "args", ")", "{", "body", "}",
            [](auto&& args) { /* action 2 */ }
    );

Internally it would look like this:

.. code-block:: cpp

  parser.rule("func")
    .production("_func#0.0", "_func#0.1",
        [](auto&& args) { /* passthrough last value */ }
    );
  parser.rule("_func#0.0")
    .production(
        "function", "id",
            [](auto&& args) { /* action 1 */ }
    );
  parser.rule("_func#0.1")
    .production(
        "(", "args", ")", "{", "body", "}",
            [](auto&& args) { /* action 2 */ }
    );

This comes with some disadvantages. Since internally, rule is being split, it can introduce `shift-reduce` conflicts which weren't there before. You also loose access to the values of symbols
that were covered by previous mid-rule actions, so for example `action 2` in example above wouldn't have access to ``function`` nor ``id`` since they are covered by `action 1`. Also keep in mind
that value from all mid-rule actions is lost and cannot be recovered. The left-hand side symbol will always be assigned value from the end-rule action.

Tokenizer states
================

Tokenizer has set of regular expressions and matches them all against the start of the input. However, it might be sometimes unncessary to match every single regular expression or even
impossible to design such that it doesn't collide with other regular expressions and always returns you the right token you want. For this purpose, you can define tokenizer states
and transition between those states as you want. Tokenizer can be in a single state at the time and can transition to any other state. Regular expression of token can be in active
in multiple states at once. States are represented using string literals. Default state is called ``@default``. This is for example useful for tokenizing string literals with escape sequences.
Upon reading ``"`` from input, you can enter special state which reads characters one by one and whenever runs into escape sequences like ``\n``, ``\t`` or any other, then it appends
corrent escaped character to the string. Upon reaching ending ``"``, we enter default state. While we are tokenizing this string literal, there is no reason to match all other regular expressions for
other tokens because we know we are in a specific context in which characters have other special meaning.

.. code-block:: cpp

  p.token("a"); // only active in default state
  p.token("b")
    .states("state1", "state2"); // only active in states state1 and state2
  p.token("c") // only active in default state
    .enter_state("state1"); // causes transition to state1
  p.token("d")
    .states("state1") // only active in state1
    .enter_state("@default"); // causes transition to default state

Input stream stack
==================

Parser in `pog` is capable of working with multiple inputs. When you call ``parse()`` method with some input stream, what actually happens is that this stream is pushed onto input stream stack.
You are able to control this input stream stack with methods ``push_input_stream()`` and ``pop_input_stream()``. Whenever parser asks tokenizer for the next token, it will be always returned from
the top-most input stream on the stack. End token actions are still performed when we reach the end of the top-most input stream but end symbol is not passed to the parser until we reach the very
last input stream on the stack. So end symbol is passed down to parser only if the input stream stack is empty or we reach the end of the top-most input stream without anyone popping it.
This can be useful for implementing things like ``include`` of another file.

.. code-block:: cpp

  static std::vector<std::string> input_streams = {
    "<stream 1>",
    "<stream 2>",
    "<stream 3>",
    "<stream 4>"
  };

  // You need to ensure that lifetime of stream is longer than its use in parser
  std::vector<std::unique_ptr<std::stringstream>> inputs;

  p.token("include [0-9]+").action([&](std::string_view str) {
    auto stream_idx = std::stoi(std::string{str.data() + 8, str.end()}); // skip 'include '
    inputs.emplace_back(std::make_unique<std::stringstream>(input_streams[stream_idx])); // create stream
    p.push_input_stream(*inputs.back().get()); // push it onto input stack
    return 0;
  });
  p.end_token().action([&](std::string_view) {
    p.pop_input_stream();
    return 0;
  });

In the example above you can see how to implement basic include-like functionality that allows you to include one of ``input_streams`` by their index. It also works recursively out of the box.
Be aware that you need to ensure the lifetime of your input stream is longer than its use in parser because parser does not take ownership of your streams.
