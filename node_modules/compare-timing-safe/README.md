[![NPM version](https://badge.fury.io/js/compare-timing-safe.svg)](https://www.npmjs.com/package/compare-timing-safe/)
[![Build Status](https://github.com/commenthol/compare-timing-safe/workflows/CI/badge.svg?branch=master&event=push)](https://github.com/commenthol/compare-timing-safe/actions/workflows/ci.yml?query=branch%3Amaster)

# compare-timing-safe

> String comparison in length constant time

Works in node and in the browser.

Node version uses `crypto` module.

### `timingSafeEqual(a, b)`

String, buffer comparison in length-constant time

**Example**

```js
import timingSafeEqual from 'compare-timing-safe'
const input = 'a'
const compareWith = 'bbbbbbbb'
timingSafeEqual(input, compareWith)
//> false
```

**Parameters**

| parameter | type           | description                          |
| --------- | -------------- | ------------------------------------ |
| `a`       | String, Buffer | String or buffer from input          |
| `b`       | String, Buffer | String or buffer to compare with `a` |

**Returns** `Boolean`, true if strings match

## Installation

Requires [nodejs](http://nodejs.org/).

```sh
$ npm install compare-timing-safe
```

## Tests

```sh
$ npm test
```

## License

Unlicense <https://unlicense.org>

## References

- [A lesson in timing attacks](https://codahale.com/a-lesson-in-timing-attacks/)
