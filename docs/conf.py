# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#

import fileinput
import os
import shutil
import sys

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
import sphinx_rtd_theme

from recommonmark.transform import AutoStructify


sys.path.insert(0, os.path.abspath("../"))


shutil.copyfile(os.path.join("..", "README.md"), "README.md")
for line in fileinput.input("README.md", inplace=True):
    if "![Image](/docs/_static/hello_zelos.png)" in line:
        print("![Image](_static/hello_zelos.png)")
    else:
        print(line, end="")

# -- Project information -----------------------------------------------------

project = "Zelos"
copyright = "2020, Zeropoint Dynamics"
author = "Zeropoint Dynamics"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.mathjax",
    "sphinx.ext.autodoc",
    "sphinx.ext.todo",
    # 'sphinx.ext.viewcode',
    "sphinx.ext.napoleon",
    "recommonmark",
    "sphinxcontrib.apidoc",
    "sphinx.ext.doctest",
    "sphinx.ext.todo",
    "sphinx.ext.intersphinx",
    "sphinxarg.ext",
]

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "api/zelos.lib.*",
    "api/zelos.regipy.*",
    "api/zelos.unicorn.rst",
    "api/zelos.lief.rst",
    "api/modules.rst",
]

apidoc_module_dir = "../src/zelos"
apidoc_output_dir = "api"
apidoc_excluded_paths = ["lib", "regipy", "unicorn", "lief"]
apidoc_separate_modules = True

nitpick_ignore = [
    ("py:class", "Any value"),
    ("py:class", "callable"),
    ("py:class", "callables"),
    ("py:class", "tuple of types"),
    ("py:class", "object"),
]

# -- Options for HTML output -------------------------------------------------


html_theme = "sphinx_rtd_theme"
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]


# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

html_logo = "_static/zelos/logo.png"
html_favicon = "_static/zelos/favicon.ico"
autodoc_member_order = "bysource"


# Setup AutoStructify
def setup(app):
    app.add_config_value(
        "recommonmark_config", {"auto_toc_tree_section": "Contents"}, True
    )
    app.add_transform(AutoStructify)
