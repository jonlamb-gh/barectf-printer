# barectf-printer

Print barectf-generated CTF trace data from file

## Install

* Download one of the pre-built [releases](https://github.com/jonlamb-gh/barectf-printer/releases)
* Or build/install from source:
  ```bash
  git clone https://github.com/jonlamb-gh/barectf-printer.git
  cd barectf-printer
  cargo install --path .
  ```

## CLI

```text
barectf-printer --help
Print barectf-generated CTF trace data from file

Usage: barectf-printer <CONFIG> [STREAM]...

Arguments:
  <CONFIG>
          The barectf effective-configuration yaml file

  [STREAM]...
          The binary CTF stream(s) file.

          Can be supplied multiple times.

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Examples

```text
barectf-printer effective_config.yaml stream

[0000000000000000] init @ default: { pc = 22 }, { ercc = 99 }, { cpu_id = 0 }, { version = "1.0.0" }
[0000000000000001] init @ default: { pc = 22 }, { ercc = 98 }, { cpu_id = 1 }, { version = "1.0.0" }
[0000000000000002] foobar @ default: { pc = 22 }, { ercc = 97 }, { val = 3, val2 = 21 }
[0000000000000003] floats @ default: { pc = 22 }, { ercc = 96 }, { f32 = 1.1, f64 = 2.2 }
[0000000000000004] enums @ default: { pc = 22 }, { ercc = 95 }, { foo = ( "A" : container = 0 ), bar = ( "C" : container = -1 ), biz = ( "RUNNING" : container = 19 ), baz = ( "on/off" : container = 0xC8 ) }
[0000000000000005] arrays @ default: { pc = 22 }, { ercc = 94 }, { foo = [ [0] = 1, [1] = 2, [2] = 3, [3] = 4 ], bar = [ [0] = "b0", [1] = "b1", [2] = "b2" ] }
[0000000000000006] shutdown @ default: { pc = 22 }, { ercc = 96 }
```

## License

See [LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT.
