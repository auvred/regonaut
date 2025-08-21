# regonaut

**regonaut** is a Go implementation of [ECMAScript Regular Expressions](https://tc39.es/ecma262/2025/multipage/text-processing.html#sec-regexp-regular-expression-objects).

It aims to be _fully compatible with JavaScript's RegExp_, including all ES2025 features and the [Annex B legacy extensions](https://tc39.es/ecma262/2025/multipage/additional-ecmascript-features-for-web-browsers.html#sec-additional-ecmascript-features-for-web-browsers).

Compatibility is verified against all [test262](https://github.com/tc39/test262) tests related to regular expressions.

That means a pattern that works in modern browsers or Node.js will behave the same way in Go.

Internally, the engine uses a backtracking approach.
See Russ Cox's [blog post](https://swtch.com/~rsc/regexp/regexp1.html) for background on backtracking vs. other regexp implementations.

## Installation

```shell
go get github.com/auvred/regonaut
```

## Usage

### TL;DR

```go
package main

import (
	"fmt"
	"github.com/auvred/regonaut"
)

func main() {
	re := MustCompile(".+(?<foo>bAr)", FlagIgnoreCase)
	m := re.FindMatch([]byte("_Bar_"))
	fmt.Printf("Groups[0] - %q\n", m.Groups[0].Data())
	fmt.Printf("Groups[1] - %q\n", m.Groups[1].Data())
	fmt.Printf("NamedGroups[\"foo\"] - %q\n", m.NamedGroups["foo"].Data())
}
```

### Unicode handling

ECMAScript and Go have different models for representing strings, and that difference is central to how this library works.

In ECMAScript, strings are defined as sequences of UTF-16 code units, and they can be ill-formed.
For example, a string may contain a lone surrogate such as `"\uD800"`, which is not a valid Unicode character on its own but is still considered a valid ECMAScript string.
You can read more about it [here](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String#utf-16_characters_unicode_code_points_and_grapheme_clusters).

Regular expressions in ECMAScript operate in two modes:

- **Non-Unicode mode:** both the pattern and the input string are treated as raw sequences of [code units](https://en.wikipedia.org/wiki/Character_encoding#Code_unit).

- **Unicode mode:** both the pattern and the input string are treated as sequences of [code points](https://en.wikipedia.org/wiki/Character_encoding#Code_point).

Unicode mode is enabled when the `u` or `v` flag is provided.

Go, on the other hand, uses UTF-8 encoded strings.
Because of this mismatch, the library provides two execution modes:

#### UTF-8 mode (recommended)

- Works with regular Go `string` values
- Unicode awareness is always implied (the `u` flag is always enabled)
- If you want features specific to the `v` flag, you must still explicitly enable it
- Both the pattern and the input must be valid UTF-8 strings
- They are processed as runes (each rune corresponds to a code point)
- Capturing group indices are reported as byte offsets within the original UTF-8 string

#### UTF-16 mode

- Works with `[]uint16` slices
- By default, each element of the slice is treated as a single code unit
- When the `u` or `v` flag is used, valid surrogate pairs are combined into single code points, while lone surrogates remain as they are
- **Use this mode only if you specifically need ECMAScript-style UTF-16 handling (e.g., when implementing or testing against a JavaScript engine)**

#### Example

```go
package main

import (
	"fmt"
	"github.com/auvred/regonaut"
)

func main() {
	var pattern = "c(.)(.)"
	var patternUtf16 = []uint16{'c', '(', '.', ')', '(', '.', ')'}

	var source = []byte("c🐱at")
	var sourceUtf16 = []uint16{'c', 0xD83D, 0xDC31, 'a', 't'}

	reUtf8 := regonaut.MustCompile(pattern, 0)
	m1 := reUtf8.FindMatch(source)
	fmt.Printf("UTF-8:                   %q, %q\n", m1.Groups[1].Data(), m1.Groups[2].Data())

	reUtf8Unicode := regonaut.MustCompile(pattern, FlagUnicode)
	m2 := reUtf8Unicode.FindMatch(source)
	fmt.Printf("UTF-8 (with 'u' flag):   %q, %q\n", m2.Groups[1].Data(), m2.Groups[2].Data())

	reUtf16 := regonaut.MustCompileUtf16(patternUtf16, 0)
	m3 := reUtf16.FindMatch(sourceUtf16)
	fmt.Printf("UTF-16:                  %#v, %#v\n", m3.Groups[1].Data(), m3.Groups[2].Data())

	reUtf16Unicode := regonaut.MustCompileUtf16(patternUtf16, FlagUnicode)
	m4 := reUtf16Unicode.FindMatch(sourceUtf16)
	fmt.Printf("UTF-16 (with 'u' flag):  %#v, %#v\n", m4.Groups[1].Data(), m4.Groups[2].Data())
}
```

Outputs:

```plaintext
UTF-8:                   "🐱", "a"
UTF-8 (with 'u' flag):   "🐱", "a"
UTF-16:                  []uint16{0xd83d}, []uint16{0xdc31}
UTF-16 (with 'u' flag):  []uint16{0xd83d, 0xdc31}, []uint16{0x61}
```

| Mode   | Flags | Matching semantics                   | Group 1 (`m.Groups[1].Data()`) | Group 2 (`m.Groups[2].Data()`) |
| ------ | ----- | ------------------------------------ | ------------------------------ | ------------------------------ |
| UTF-8  | —     | Code points (UTF-8 mode implies `u`) | `"🐱"`                         | `"a"`                          |
| UTF-8  | `u`   | Code points                          | `"🐱"`                         | `"a"`                          |
| UTF-16 | —     | Code units (surrogates not paired)   | `[]uint16{0xd83d}`             | `[]uint16{0xdc31}`             |
| UTF-16 | `u`   | Code points (surrogates paired)      | `[]uint16{0xd83d, 0xdc31}`     | `[]uint16{0x61}`               |

> [!NOTE]
> The [U+1F431 CAT FACE](https://codepoints.net/U+1F431) (🐱).
> In UTF-16 without `u`, it appears as two separate surrogate code units (`0xD83D`, `0xDC31`).
> With `u`, those are paired into one code point.

## Local Development

### Prerequisites

- Go
- Node.js with Type Stripping support (version 22.18.0+, 23.6.0+, or 24+)
- pnpm

### Setup

Make sure the test262 submodule is initialized:

```shell
git submodule update --init
```

Generate the `test262` tests:

```shell
cd tools
pnpm i
pnpm run gen-test262-tests
cd ..
```

### Running tests

```shell
# Run all tests, including test262
go test

# Run all tests, except test262
go test -skip 262

# Run all test, excluding generated property-escapes tests (they are slow)
go test -skip 262/built-ins/RegExp/property-escapes/generated
```

## License

[MIT](./LICENSE)
