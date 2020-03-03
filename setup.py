#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Note: To use the 'upload' functionality of this file, you must:
#   $ pipenv install twine --dev

import codecs
import os
import re
import sys

from shutil import rmtree

from setuptools import Command, find_packages, setup


NAME = "zelos"
PACKAGES = find_packages(where="src")
META_PATH = os.path.join("src", "zelos", "__init__.py")
KEYWORDS = ["emulation", "dynamic analysis", "binary analysis"]
PROJECT_URLS = {
    "Documentation": "https://zelos.zeropointdynamics.com/",
    "Bug Tracker": "https://github.com/zeropointdynamics/zelos/issues",
    "Source Code": "https://github.com/zeropointdynamics/zelos",
}
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Natural Language :: English",
    "License :: OSI Approved :: GNU Affero General Public License v3",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
]
INSTALL_REQUIRES = [
    "wheel",
    "colorama==0.4.1",
    "termcolor==1.1.0",
    "capstone==4.0.1",
    "sortedcontainers==2.1.0",
    "verboselogs==1.7",
    "dnslib==0.9.10",
    "hexdump==3.3",
    "dpkt==1.9.2",
    "coloredlogs==10.0",
    "configargparse==0.15.1",
    "pypacker==4.9",
    "lief>=0.9.0",
    "unicorn==1.0.2rc1",
]
EXTRAS_REQUIRE = {
    "docs": [
        "sphinx",
        "sphinx_rtd_theme",
        "sphinxcontrib-apidoc",
        "recommonmark",
        "sphinx-argparse",
    ],
    "tests": [
        "coverage",
        "hypothesis",
        "pympler",
        "pytest>=4.3.0",
        "pytest-xdist",
    ],
}
EXTRAS_REQUIRE["dev"] = (
    EXTRAS_REQUIRE["tests"] + EXTRAS_REQUIRE["docs"] + ["pre-commit", "tox"]
)
EXTRAS_REQUIRE["azure-pipelines"] = EXTRAS_REQUIRE["tests"] + [
    "pytest-azurepipelines"
]

########################################################################

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    """
    Build an absolute path from *parts* and and return the contents of
    the resulting file.  Assume UTF-8 encoding.
    """
    with codecs.open(os.path.join(HERE, *parts), "rb", "utf-8") as f:
        return f.read()


META_FILE = read(META_PATH)


def find_meta(meta):
    """
    Extract __*meta*__ from META_FILE.
    """
    meta_match = re.search(
        r"^__{meta}__ = ['\"]([^'\"]*)['\"]".format(meta=meta), META_FILE, re.M
    )
    if meta_match:
        return meta_match.group(1)
    raise RuntimeError("Unable to find __{meta}__ string.".format(meta=meta))


VERSION = find_meta("version")
URL = find_meta("url")
LONG = (
    read("README.md")
    + "\n\n"
    + read("CHANGELOG.md")
    + "\n\n"
    + read("AUTHORS.md")
)


class UploadCommand(Command):
    """Support setup.py upload."""

    description = "Build and publish the package."
    user_options = []

    @staticmethod
    def status(s):
        """Prints things in bold."""
        print("\033[1m{0}\033[0m".format(s))

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        try:
            self.status("Removing previous builds…")
            rmtree(os.path.join(HERE, "dist"))
        except OSError:
            pass

        self.status("Building Source and Wheel (universal) distribution…")
        os.system(
            "{0} setup.py sdist bdist_wheel --universal".format(sys.executable)
        )

        self.status("Uploading the package to PyPI via Twine…")
        os.system("twine upload dist/*")

        self.status("Pushing git tags…")
        os.system("git tag v{0}".format(VERSION))
        os.system("git push --tags")

        sys.exit()


if __name__ == "__main__":
    setup(
        name=NAME,
        description=find_meta("description"),
        license=find_meta("license"),
        url=URL,
        project_urls=PROJECT_URLS,
        version=VERSION,
        author=find_meta("author"),
        author_email=find_meta("email"),
        maintainer=find_meta("author"),
        maintainer_email=find_meta("email"),
        keywords=KEYWORDS,
        long_description=LONG,
        long_description_content_type="text/markdown",
        packages=PACKAGES,
        package_dir={"": "src"},
        python_requires=">=3.6.0",
        zip_safe=False,
        classifiers=CLASSIFIERS,
        install_requires=INSTALL_REQUIRES,
        extras_require=EXTRAS_REQUIRE,
        include_package_data=True,
        options={"bdist_wheel": {"universal": "1"}},
        setup_requires=["wheel"],
        cmdclass={"upload": UploadCommand},
        entry_points={"console_scripts": [f"{NAME} = {NAME}.__main__:main"]},
    )
