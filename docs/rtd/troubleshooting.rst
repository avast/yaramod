===============
Troubleshooting
===============

If you encounter a problem using Yaramod, it is usually easy to determine which of the four components the problem is related to:

* A ``ParserError`` indicates parsing problem and the message should include the first problematic token of the imput.
* A ``BuilderError`` probably means that your service uses the Builder incorrectly.
* If you use the ``getTextFormatted()`` (``text_formatted`` in Python) method of a YARA file and the output seems wrong, the problem will be probably in the the ``getText`` method of the ``TokenStream`` class. Please create a ticket and supply the input and the wrong output with some explanation so we can look into it.
* There can also be some problems when using modifying visitors. In the case your modifying visitor modifies the unformatted text very well, but the formatted text is wrong (usually missing tokens or bad ordering of tokens) it may indicate unused method ``cleanUpTokenStreams`` of the ``ModifyingVisitor`` class. Or the method could be used in a wrong matter. Please consult our examples in the section `Modifying Rulesets <https://yaramod.readthedocs.io/en/latest/modifying_rulesets.html>`_ and if that does not help consider contacting the authors.
