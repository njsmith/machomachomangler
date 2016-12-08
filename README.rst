Mach-O Mach-O Mangler
=====================

.. image:: https://travis-ci.org/njsmith/machomachomangler.svg?branch=master
   :target: https://travis-ci.org/njsmith/machomachomangler
   :alt: Automated test status (Travis)

.. image:: https://ci.appveyor.com/api/projects/status/9p8cuhx8vwn2i2jp?svg=true
   :target: https://ci.appveyor.com/project/njsmith/machomachomangler
   :alt: Automated test status (Appveyor)

.. image:: https://codecov.io/gh/njsmith/machomachomangler/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/njsmith/machomachomangler
   :alt: Test coverage


This is a little library for mangling Mach-O and PE files in various
ways. These are the formats used for executables and shared libraries
on MacOS and Windows, respectively. (If you want the equivalent for
for Linux, then check out `patchelf
<https://github.com/NixOS/patchelf>`__.)


Macho-O features
----------------

Some rather specialized (and complex) Mach-O mangling tools designed
to support `the pynativelib proposal
<https://github.com/njsmith/wheel-builders/blob/pynativelib-proposal/pynativelib-proposal.rst>`__
to allow native libraries to be distributed as standalone `wheel files
<https://pypi.python.org/pypi/wheel>`__. Specifically this includes:

* For pynativelib libraries: a tool that takes a dylib, and a mangling
  rule, and applies the mangling rule to all the exported
  symbols. E.g., it can convert a library that exports ``SSL_new``
  into one that exports ``pynativelib_openssl__SSL_new``. It also
  changes the library id while it's at it, e.g. from ``ssl.dylib`` ->
  ``pynativelib_openssl__ssl.dylib`` (like ``install_name_tool -id``)

  Additionally: a tool that creates a "placeholder" library, which
  imports the mangled library described above, and then re-exports the
  symbols under their original names.

* For code that wants to use a pynativelib library: a tool that
  takes a dylib/bundle/executable, a list of "original" dylibs, and
  for each "original" dylib, a newname for that dylib, and a
  mangling rule. It then (a) replaces the import of the original
  dylib with an absolute import of the new dylib name from a
  non-existent directory, (b) marks this as a "weak" import, (c)
  applies the mangling rule to all symbols imported from this dylib,
  (d) marks these symbols for lookup in the flat namespace.

It turns out that this *exact* combination of things is the only way
provided for by the MacOS linker/loader to have dylib/bundle A linked
against dylib B where the relative on-disk location of A and B is not
known until after the executable starts. I promise it will all make
sense once I have a chance to write it up properly...

Some known limitations of the Mach-O mangling code:

- Unsurprisingly, this kind of patching does not play well with code
  signing. The code doesn't take any special case with signatures;
  they'll probably just get messed up. If you want to sign your
  binaries, then do your mangling first before signing.

- We currently only rewrite the new-style DYLD_INFO symbol table
  (introduced in 10.5), not the (almost?) totally redundant
  SYMTAB/DYSYMTAB symbol table. (Interesting fact: all Mach-O binaries
  include two completely different representations of their symbols
  tables. The new one is more compact, to save space, but then they
  keep the old one around for compatibility, so... anyway.) As far as
  I can tell, the only thing in in modern MacOS that still uses
  SYMTAB/DYSYMTAB is ``dladdr``, and I don't think anyone is relying
  on ``dladdr`` output for, well... anything? I think worst case, you
  might end up seeing the original symbol names inside a debugger or
  profiler? But this wouldn't be *too* hard to fix if it becomes a
  problem.

- It doesn't do any special handling of the DYLD_INFO weak_bind table,
  or weak exports. (NB these have nothing to do
  ``__attribute__((weak))`` or ``__attribute__((weak_import))`` or any
  of the mentions of the word ``weak`` in the ``ld`` man page – I
  think they're for implementing `vague linkage
  <http://www.airs.com/blog/archives/52>`__.) This is *probably* not a
  disastrous option, but I'm not 100% sure whether it's actually
  correct – it's an incredibly obscure part of the Mach-O format, and
  Mach-O is pretty obscure to start with. Fortunately this feature is
  only used by C++ libraries, so we can get started without it.

- When mangling imports, we convert any lazy imports (that need
  mangling) into eager imports. This is required because the lazy
  import stubs hard-code the memory layout of the import table into
  immediate constants inside the stub assembly itself, and I do not
  feel like trying to automatically rewrite x86-64 opcodes. Instead,
  we leave the lazy import table alone (so all the unmangled lazy
  imports can continue to use it), and eagerly bind all the mangled
  imports, so the unmangled stubs never get called.

- I noticed some new code dyld in MacOS 10.12 that imposes some
  annoying arbitrary restrictions on which order the different bits of
  DYLD_INFO appear in the file. This should only affect libraries that
  are built with 10.12 as their minimum required version, so for folks
  trying to build stuff for general distribution this shouldn't matter
  for a while. This also isn't hard to fix, it just means that we'll
  probably have to start making some pointless redundant copies of
  bits of the file that we *didn't* change, just so that the second
  copy can be placed after the bit of the file that we did change,
  which is tiresome and I haven't gotten around to it yet.

- When mangling imports, we don't check for re-exports, which are also
  a kind of import. Should probably fix this...


PE features
-----------

A tool that can read in a PE file (``.exe`` or ``.dll``) that is
currently linked to ``foo.dll``, and rewrite it so that it becomes
linked to ``bar.dll`` instead (similar to ``patchelf --replace`` on
Linux, or ``install_name_tool -change`` on OS X). This is useful for
avoiding naming collisions between different versions of the same
library.

For example, suppose you have two Python extensions ``A.dll`` and
``B.dll``, that are distributed separately by different people. They
both contain some fortran code linked to to ``libgfortran-3.dll``, so
both packages ship a copy of ``libgfortran-3.dll``. Because of the way
Windows DLL loading works, what will happen is that if I load
``A.dll`` first, then *both* ``A.dll`` and ``B.dll`` will end up using
A's copy of ``libgfortran-3.dll``, while B's copy will be ignored. (Or
vice-versa if I import B first.) This will happen even if I arrange
things so that A's copy is not on the DLL search path at the time that
B is loaded -- Windows always checks for already-loaded DLL's with a
given basename before it actually checks the DLL search path (modulo
some complications around SxS assemblies, but you don't really want to
go there).

This is bad, because there's no guarantee that ``B.dll`` will work
with A's version of ``libgfortran-3.dll`` (e.g., A's copy might be too
old for B). Welcome to `DLL hell
<https://en.wikipedia.org/wiki/DLL_Hell>`_!

We could avoid all this by renaming the colliding libraries to have
different names, e.g. ``libgfortran-3-for-A.dll`` and
``libgfortran-3-for-B.dll``. But if we just rename the files, then
everything will break, because ``A.dll`` is looking for
``libgfortran-3.dll``, not ``libgfortran-3-for-A.dll``.

This is where ``machomachomangler`` comes in: it lets you patch
``A.dll`` so that it's linked to ``libgfortran-3-for-A.dll``. And then
everything works. Hooray.

This basically solves the same problem as private SxS assemblies,
except better in all ways: it's simpler (no XML manifests), more
flexible (no finicky requirements for the filesystem layout), and
doesn't require reading the awful SxS assembly documentation.

Example usage::

  $ python3 -m machomachomangler.cmd.redll A.dll A-patched.dll libgfortran-3.dll libgfortan-3-for-A.dll

There's an example in ``example/`` then you can play with. E.g. on
Debian with a mingw-w64 cross-compiler and wine installed::

  $ cd pe-example/

  $ ./build.sh
  + i686-w64-mingw32-gcc -shared test_dll.c -o test_dll.dll
  + i686-w64-mingw32-gcc test.c -o test.exe -L. -ltest_dll
  + i686-w64-mingw32-strip test.exe

  $ wine test.exe
  dll_function says: test_dll

  $ mv test_dll.dll test_dll_renamed.dll

  # Apparently wine's way of signalling a missing DLL is to fail silently.
  $ wine test.exe || echo "failed -- test_dll.dll is missing"
  failed -- test_dll.dll is missing

  $ PYTHONPATH=.. python3 -m machomachomangler.cmd.redll test.exe test-patched.exe test_dll.dll test_dll_renamed.dll

  # Now it works again:
  $ wine test-patched.exe
  dll_function says: test_dll

Some known limitations of the PE dll-import-switcheroo code:

- The command line tool could be less minimalist.

- GNU ``objdump`` has a bug where it can't read the import tables of
  our patched PE files -- it just shows all of the import table until
  it hits the patched entry, and then it stops displaying
  anything. (The issue is that ``binutils`` wants all the data
  involved in the import tables to come from a single PE section.)
  However, I've tried giving the patched files to Dependency Walker,
  ``wine``, and Windows itself, and they all handle them fine -- so
  the files are okay, it's just a bug in ``objdump``. Just be warned
  that if you're trying to use ``objdump`` to check if the patching
  worked, then it's almost certainly going to tell you a confusing
  lie.

- Unsurprisingly, this kind of patching does not play well with code
  signing. We try to at least clear any existing signatures (so that
  the binary becomes unsigned, rather than signed with an invalid
  signature), but this hasn't been tested.

- We don't try to handle files with trailing data after the end of the
  PE file proper. This commonly occurs with e.g. self-extracting
  archives and installers. Shouldn't be a big deal in theory, but I
  did find that when compiling a simple ``.exe`` with mingw-w64 the
  tool refused to work until I had run ``strip`` on the binary, even
  though in theory this should work fine -- so probably there's some
  improvements possible.

  [Note to self: it looks like this is a GNU extension for putting
  long section names into PE files, which I guess are they use for
  their debug format -- this is `documented here
  <https://sourceware.org/binutils/docs/bfd/coff.html>`__, search for
  "Coff long section names". It's probably not hard to handle this
  better, e.g. by stripping it ourself or even fixing it up.]

- We don't try to update the PE header checksum, since the algorithm
  for doing this is (nominally) a secret, and I'm informed that for
  regular user-space code there's nothing that actually cares about
  whether it's correct. But my information could be wrong. (Note: it
  looks like binutils might know how to compute this checksum? I'm not
  sure.)

  [Update: Stefan Kanthak informs me that this algorithm is well
  known, and in fact it looks `pefile has an MIT-licensed Python
  implementation
  <https://github.com/erocarrera/pefile/blob/master/pefile.py#L5150>`_
  so I guess it might be good to fix this at some point.]


General limitations
-------------------

Only tested on **Python 3.4 and 3.5**. Probably any Python 3 will
work, and Python 2 definitely won't without some fixes. (There's lots
of fiddly byte-string handling.)

I'm lazy, so I just load the whole binary files into memory -- maybe
several copies of it. This actually wouldn't be too hard to fix (using
memory mapping etc.) but I guess it doesn't matter that much because
`who has multi-gigabyte Mach-O/PE images?
<http://tvtropes.org/pmwiki/pmwiki.php/Main/WhatCouldPossiblyGoWrong>`_?


Contact
-------

wheel-builders@python.org


License
-------

It's Saturday afternoon, I've got the flu or something, and I'm
spending my free time writing software to make some proprietary
operating systems -- ones that are backed by one of the world's larger
corporations -- better able to compete for developers with other,
better-designed operating systems. I mean, I'm not saying that poring
over the PE/COFF specification isn't fun!  But it's not *that*
fun. (And honestly the Mach-O docs are absolutely terrible, to the
extent they exist at all.)

To assuage my annoyance, this software is licensed under the *GNU
Affero General Public License as published by the Free Software
Foundation, either version 3 of the License or (at your option)
any later version*. See ``LICENSE.txt`` for details.

This **shouldn't have any effect** on most uses, since it only affects
people who are redistributing this software or running it on behalf of
other people; you can *use* this software to manipulate your
BSD-licensed DLLs, your proprietary-licensed DLLs, or whatever you
like, and that's fine. The license affects the code for
machomachomangler itself; not the code you run it on.

However, if for some reason you or your company have some kind of
allergy to this license, send me `an email
<mailto:njs@pobox.com>`_ and we'll work out an appropriate tithe.

Also, to preserve our options in case I get over this fit of pique,
please **license all contributions under the MIT license**. (I
definitely will not switch to any proprietary license, but might
switch to a permissive OSS license.) Thanks!


Code of conduct
---------------

Contributors are requested to follow our `code of conduct
<https://github.com/njsmith/machomachomangler/blob/master/CODE_OF_CONDUCT.md>`_
in all project spaces.
