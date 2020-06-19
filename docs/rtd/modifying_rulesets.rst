==================
Modifying Rulesets
==================

Modifying Metas
===============
In Yaramod, we are able to modify existing Yara rules through many methods. For example, we can add new metas with method ``Rule::addMeta(const std::string& name, const Literal& value)`` which inserts a new meta also into the TokenStream. This method can be used through python as ``add_meta`` as follows:

.. code::

  yara_file = yaramod.Yaramod().parse_string(
  '''
  rule rule_with_added_metas {
    condition:
      true
  }'''
  )

  rule = yara_file.rules[0]
  rule.add_meta('int_meta', yaramod.Literal(42))
  rule.add_meta('bool_meta', yaramod.Literal(False))


This will add both ``meta`` and ``:`` tokens and create two metas and the formatted text will look as follows:

.. code::

  rule rule_with_added_metas
  {
    meta:
      int_meta = 42
      bool_meta = false
    condition:
      true
  }

We can also modify existing metas using python bindings ``Rule::get_meta_with_name`` and ``Meta::value``. The following code will change the integer value ``42`` of ``int_meta`` into string ``forty two``:

.. code::

  meta = rule.get_meta_with_name('int_meta')
  meta.value = yaramod.Literal('forty two')

With the following result:

.. code::

  rule rule_with_added_metas
  {
    meta:
      int_meta = "forty two"
      bool_meta = false
    condition:
      true
  }


Modifying Visitors
==================

The Conditions in Yaramod
-------------------------

To demonstrate how to alter conditions of Yara rules we first need to make sure we understand their structure.

Conditions in Yaramod are tree-like structures where each node is a derived class of the ``Expression`` class. Based on the arity of each expression is the number of nodes under it. The leaves of the tree correspond to the expressions of arity 0 such as ``EntrypointExpression`` or ``StringExpression``. The expressions like ``NotExpression`` or other derived classes of ``UnaryOpExpression`` always have one other expression under them. And then we also have ``BinaryOpExpression`` with arity 2 or even more, because the ``ForExpression`` has another 3 expressions referenced under it.

Visiting Expressions
--------------------

Yaramod provides two kinds of Visitors enabling the user to observe or modify existing Expressions. This page is about more interesting modifying Visitors:

Both ``ObservingVisitor`` and ``ModifyingVisitor`` classes define a visit method for each derived ``Expression`` class as a parameter. These methods are pre-defined not to change/do anything in the expression they are called with. The only thing these pre-defined methods do is they trigger visiting of all subexpressions. This means, that after calling a visit on an expression, the visit methods are recursively called upon each of the subnodes in the expression tree structure. Until we modify the visit methods, each such call performs no actions on the nodes.

We will now focus on the ``ModifyingVisitor`` class which supplies also the ``modify`` method with an ``Expression* expr`` as a parameter. This method arranges that a correct ``visit`` method is called with ``expr`` as the parameter. Let us now describe three types of ModifyingVisitors we can write with three examples.



Custom Visitor Examples
-----------------------

Following visitor provides specification of the ``visit`` method for ``StringExpression``. It 'to uppers' the ``id`` of the ``StringExpression``. It is modifying existing ``StringExpression`` instance:

.. code::

  class StringExpressionUpper(yaramod.ModifyingVisitor):
    def process(self, yara_file: yaramod.YaraFile):
      for rule in yara_file.rules:
        self.modify(rule.condition)
    def visit_StringExpression(self, expr: yaramod.Expression):
      expr.id = expr.id.upper()

We can now use this visitors instance ``visitor`` to alter all conditions of rules present in a given yara file simply by calling ``visitor.process(yara_file)``. The next example will show a case when we replace existing visited node in the ``Expression`` syntax tree by another new node:

.. code::

  def visit_RegexpExpression(self, expr: yaramod.Expression):
    output = yaramod.regexp('abc', 'i').get()
    expr.exchange_tokens(output)
    return output

This ``visit`` methods requires calling of a ``exchange_tokens`` method which deletes all Tokens that the original expression refered to. Then it extracts all tokens from the supplied new Expression and moves them to place where the original expression had its tokens stored.

In the third example we will show how to deal with a situation where we need to modify existing expression while keeping part of it's subexpressions. The following approach will let us use Yaramod Expression Builders to create new Expressions from existing expressions that are already used in our rule.

Let's now assume that we need to modify each ``EqExpression`` in the expression syntax tree. We can do it by writing our own derived class of ``ModifyingVisitor``. The new class will override the ``visit(EqExpression* expr)`` method in the following manner:

.. code::

  def visit_EqExpression(self, expr: yaramod.Expression):
    context = yaramod.TokenStreamContext(expr)

    expr.left_operand.accept(self)
    expr.right_operand.accept(self)

    output = (yaramod.YaraExpressionBuilder(expr.right_operand) != yaramod.YaraExpressionBuilder(expr.left_operand)).get()

    self.cleanUpTokenStreams(context, output)
    return output

The first line is simply creating a snapshot ``context`` of the ``TokenStream`` and first and last ``Token`` of the processed ``Expression``.
Because here we deal with an ``Expression`` of non-zero arity, we have to trigger the Visitor also on it's subnodes. This happens on the next two lines.
Then a new expression ``output`` is created. The ``cleanUpTokenStreams`` method makes sure, that all remaining tokens of the old version of the expression, that have not been used by the builder, are deleted. Then all tokens maintained by the builder are moved back to the original TokenStream on the right place.
