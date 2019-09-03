.. _installation:

============
Installation
============

This page describes installation of `pog` and how you can integrate it into your own project.

Getting source code
===================

At first, you'll need to obtain source code. If you want the latest released version, which should always be stable, you can download one from `GitHub releases page <https://github.com/metthal/pog/releases>`_.
If you want to get the latest development version or you are intersted in the development of the library, you can also get the source code using ``git``. To clone the repository run:

.. code-block:: bash

  git clone https://github.com/metthal/pog.git


Requirements
============

In order to use `pog`, you will need:

* C++ compiler with C++17 support
* CMake 3.8+
* `re2 <https://github.com/google/re2>`_
* `fmt <https://github.com/fmtlib/fmt>`_

You can install them from your distribution repositories. For Ubuntu based distributions use:

.. code-block:: bash

  apt-get install libfmt-dev libre2-dev

For Red Hat based distributions use:

.. code-block:: bash

  dnf install fmt-devel re2-devel

For macOS use:

.. code-block:: bash

  brew install fmt re2

There is also an option to download ``re2`` or ``fmt`` while building the project. See :ref:`compilation` for more information regarding this.

.. _compilation:

Compilation
===========

`pog` itself is header-only library but it has dependencies which are not header-only. To compile it run:

.. code-block:: bash

  cmake -DCMAKE_BUILD_TYPE=Release [OPTIONS] ..
  cmake --build . --target install

Other options you can use:

* ``POG_DOWNLOAD_RE2`` - ``re2`` will be downloaded during build-time. It will be compiled and installed as ``libpog_re2.a`` (or ``pog_re2.lib`` on Windows) together with the library. (Default: ``OFF``)
* ``POG_DOWNLOAD_FMT`` - ``fmt`` will be downloaded during build-time. It will be compiled and installed as ``libpog_fmt.a`` (or ``pog_fmt.lib`` on Windows) together with the library. (Default: ``OFF``)
* ``POG_TESTS`` - Build tests located in ``tests/`` folder. (Default: ``OFF``)
* ``POG_EXAMPLES`` - Build examples located in ``examples/`` folder. (Default: ``OFF``)

Usage
=====

``pog`` will be installed together with CMake configuration files which make integration into other CMake projects much more easier. If you use CMake in your project put following lines in your ``CMakeLists.txt`` file and that should be it.

.. code-block:: cmake

  find_package(pog REQUIRED)
  target_link_libraries(<YOUR_TARGET> pog::pog)

For projects which use other build systems, you can use `pkgconfig <https://www.freedesktop.org/wiki/Software/pkg-config/>`_ files which are installed too. To obtain which compilation flags are needed run following commands in your shell or integrate it directly into your build system.

.. code-block:: bash

  pkg-config --cflags pog
  pkg-config --libs pog

To use `pog` from your source code, include file ``<pog/pog.h>``. Everything in `pog` is located inside ``pog`` namespace. Example:

.. code-block:: cpp

  #include <pog/pog.h>

  int main()
  {
      pog::Parser<Value> parser;

      // your parser definition
  }
