mackerel-plugin-httpstat
=====================

httpstat metrics plugin for mackerel.io agent.

## Synopsis

```shell
mackerel-plugin-httpstat [-url=<url>] [-tempfile=<tempfile>]
```

## Example of mackerel-agent.conf

```
[plugin.metrics.httpstat]
command = "/path/to/mackerel-plugin-httpstat -u https://example.com -metric-key-prefix=httpstat-example.com"
```

## License

This software is released under the MIT License, see LICENSE.

## See Also

* [golang httpstat implementation](https://github.com/davecheney/httpstat)
