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
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))

# -- Project information -----------------------------------------------------

project = 'MCSI Library'
copyright = '2022, Mossé Cyber Security Institute'

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
  'sphinx.ext.duration',
  'myst_parser',
  'sphinx.ext.autodoc',
  'sphinxext.opengraph',
  'sphinx_sitemap',
  'sphinx.ext.viewcode',
  'sphinx_togglebutton'
]

html_baseurl = "https://mcsi-library.readthedocs.io/"

html_title = "MCSI Library"

sitemap_filename = "sitemap-index.xml"

sitemap_locales = [None]

html_extra_path = ["_html"]

myst_enable_extensions = [
  "amsmath",
  "colon_fence",
  "deflist",
  "dollarmath",
  "fieldlist",
  "html_admonition",
  "html_image",
  "replacements",
  "smartquotes",
  "strikethrough",
  "substitution",
  "tasklist"
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
# These folders are copied to the documentation's HTML output
html_static_path = ['_static']

html_css_files = [
  'css/helpers.css'
]

html_theme = "sphinx_book_theme"

html_logo= "assets/logo.svg"

html_theme_options = {
  "logo_only": True,
  "home_page_in_toc": True, 
  "use_download_button": False,
  "use_fullscreen_button": False
  }

html_favicon = 'assets/favicon.png'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_show_sourcelink = False