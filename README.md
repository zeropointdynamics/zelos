![PyPI](https://img.shields.io/pypi/v/zelos)
[![Build Status](https://dev.azure.com/kevin0853/zelos/_apis/build/status/zeropointdynamics.zelos?branchName=master)](https://dev.azure.com/kevin0853/zelos/_build/latest?definitionId=1&branchName=master)
[![codecov](https://codecov.io/gh/zeropointdynamics/zelos/branch/master/graph/badge.svg)](https://codecov.io/gh/zeropointdynamics/zelos)
[![Documentation Status](https://readthedocs.org/projects/zelos/badge/?version=latest)](https://zelos.readthedocs.io/en/latest/?badge=latest)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/zelos)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>

# Zelos
Zelos (**Z**eropoint **E**mulated **L**ightweight **O**perating **S**ystem) is a python-based binary emulation platform. One use of zelos is to quickly assess the dynamic behavior of binaries via command-line or python scripts. All syscalls are emulated to isolate the target binary. Linux x86_64 (32- and 64-bit), ARM and MIPS binaries are supported.

![Image](/docs/_static/hello_zelos.png)

[Full documentation](https://zelos.readthedocs.io/en/latest/index.html) is available [here](https://zelos.readthedocs.io/en/latest/index.html).

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install zelos.

```bash
pip install zelos
```

## Basic Usage

### Command-line
To emulate a binary with default options:

```console
$ zelos my_binary
```

To view the instructions that are being executed, add the `-v` flag:
```console
$ zelos -v my_binary
```

You can print only the first time each instruction is executed, rather than *every* execution, using `--fasttrace`:
```console
$ zelos -v --fasttrace my_binary
```

By default, syscalls are emitted on stdout. To write syscalls to a file instead, use the `--strace` flag:
```console
$ zelos --strace path/to/file my_binary
```

Specify any command line arguments after the binary name:
```console
$ zelos my_binary arg1 arg2
```

### Programmatic
```python
import zelos

z = zelos.Zelos("my_binary")
z.start(timeout=3)
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

### Local Development Environment

First, create a new python virtual environment. This will ensure no package version conflicts arise:

```console
$ python3 -m venv ~/.venv/zelos
$ source ~/.venv/zelos/bin/activate
```

Now clone the repository and change into the `zelos` directory:

```console
(zelos) $ git clone git@github.com:zeropointdynamics/zelos.git
(zelos) $ cd zelos
```

Install an *editable* version of zelos into the virtual environment. This makes `import zelos` available, and any local changes to zelos will be effective immediately:

```console
(zelos) $ pip install -e '.[dev]'
```

At this point, tests should pass and documentation should build:

```console
(zelos) $ pytest
(zelos) $ cd docs
(zelos) $ make html
```

Built documentation is found in ``docs/_build/html/``.

Install zelos pre-commit hooks to ensure code style compliance:

```console
(zelos) $ pre-commit install
```

In addition to automatically running every commit, you can run them anytime with:

```console
(zelos) $ pre-commit run --all-files
```

#### Windows Development:

Commands vary slightly on Windows:

```console
C:\> python3 -m venv zelos_venv
C:\> zelos_venv\Scripts\activate.bat
(zelos) C:\> pip install -e .[dev]
```

## License
[AGPL v3](https://www.gnu.org/licenses/agpl-3.0.en.html)
