# Zelos Remote Debug Server (zdb)

The `zdbserver` enables remote debugging with `zelos` over an HTTP/XML-based RPC protocol, i.e. the python `xmlrpc` protocol.

## Basic Usage

To remotely debug a binary with default options:

```console
$ python -m zelos.tools.zdbserver my_binary
```

All the standard `zelos` flags can be used here as well. By default, the debug server is hosted on http://localhost:62433. The port can be changed:

```console
$ python -m zelos.tools.zdbserver --debug_port 555 my_binary
```

Currently, the only `zdb` client is an `angr` [tool](https://github.com/zeropointdynamics/angr-zelos-target) that integrates symbolic execution with `zelos`.
