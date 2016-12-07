from setuptools import setup, find_packages

from machomachomangler import __version__

setup(
    name="machomachomangler",
    version=__version__,
    description=
        "Tools for mangling Mach-O and PE binaries",
    long_description=open("README.rst").read(),
    author="Nathaniel J. Smith",
    author_email="njs@pobox.com",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "attrs",
    ],
    url="https://github.com/njsmith/machomachomangler",
    # This means, just install *everything* you see under the package
    # directory, even if it doesn't look like a source file, so long as it
    # appears in MANIFEST.in:
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Operating System :: Microsoft",
        "Operating System :: MacOS :: MacOS X",
        "Topic :: Software Development :: Build Tools",
        "Topic :: Software Development :: Compilers",
        ],
)
