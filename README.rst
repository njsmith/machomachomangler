redll
=====

This is a little tool that can read in a PE file (``.exe`` or
``.dll``) that is currently linked to ``foo.dll``, and rewrite it so
that it becomes linked to ``bar.dll`` instead (similar to ``patchelf
--replace`` on Linux, or ``install_name_tool -change`` on OS X). This
is useful for avoiding naming collisions between different versions of
the same library.

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

This is where ``redll`` comes in: it lets you patch ``A.dll`` so that
it's linked to ``libgfortran-3-for-A.dll``. And then everything
works. Hooray.

This basically solves the same problem as private SxS assemblies,
except better in all ways: it's simpler (no XML manifests), more
flexible (no finicky requirements for the filesystem layout), and
doesn't require reading the awful SxS assembly documentation.


Notes / caveats
---------------

Currently this is a one-day hack. So the usual "no warranty express of
implied" stuff is extra true. Some particular known limitations:

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

- We don't try to update the PE header checksum, since the algorithm
  for doing this is a secret, and I'm informed that for regular
  user-space code there's nothing that actually cares about whether
  it's correct. But my information could be wrong.

- There's no test suite, so this whole thing will dissolve into a
  million tiny spikey shards of brokenness as soon as my back is
  turned.

- Only tested on **Python 3.4**. Probably any Python 3 will work, and
  Python 2 definitely won't without some fixes. (There's lots of
  fiddly byte-string handling.)

- Currently missing standard niceties like ``setup.py``, docs,
  copyright headers, etc.


Example
-------

::

  $ python3 -m redll A.dll A-patched.dll libgfortran-3.dll libgfortan-3-for-A.dll

There's an example in ``example/`` then you can play with. E.g. on
Debian with a mingw-w64 cross-compiler and wine installed::

  $ cd example/

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

  $ PYTHONPATH=.. python3 -m redll test.exe test-patched.exe test_dll.dll test_dll_renamed.dll

  # Now it works again:
  $ wine test-patched.exe
  dll_function says: test_dll


Contact
-------

wheel-builders@python.org


License
-------

It's Saturday afternoon, I've got the flu or something, and I'm
spending my free time writing software to make a proprietary operating
system -- one that is backed by one of the world's larger corporations
-- better able to compete for developers with other, better-designed
operating systems. Because I guess Microsoft can't afford to pay for
such things, and is dependent on charity. I mean, I'm not saying that
poring over the PE/COFF specification isn't fun! But it's not *that*
fun.

To assuage my annoyance, this software is licensed under the *GNU
Affero General Public License as published by the Free Software
Foundation, either version 3 of the License or (at your option)
any later version*. See ``LICENSE.txt`` for details.

This **shouldn't have any effect** on most uses, since it only affects
people who are redistributing this software or running it on behalf
of other people; you can *use* this software to manipulate your
BSD-licensed DLLs, your proprietary-licensed DLLs, or whatever you
like, and that's fine. The license affects the code for redll itself;
not the code you run it on.

However, if for some reason you or your company have some kind of
allergy to this license, send me `an email
<mailto:njs@pobox.com>`_ and we'll work out an appropriate tithe.

Also, to preserve our options in case I get over this fit of
pique, please **license all contributions under the MIT
license**. Thanks!
