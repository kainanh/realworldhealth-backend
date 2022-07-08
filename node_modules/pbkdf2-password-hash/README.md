# pbkdf2-password-hash

> hash password with pbkdf2

[![NPM version](https://badge.fury.io/js/pbkdf2-password-hash.svg)](https://www.npmjs.com/package/pbkdf2-password-hash/)

Generation and validation of passwords using PBKDF2 hashes.

Safety is obtained by using safe digest, large number of iterations and large key-length for PBKDF2.
Per default uses `sha512` with 512 bit key and 120,000 iterations.

This is as recommended by [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).

## ToC

<!-- !toc (minlevel=2 omit="ToC") -->

* [Example](#example)
* [API](#api)
  * [`hash(password, [salt], [opts])`](#hashpassword-salt-opts)
  * [`compare(password, passwordHash)`](#comparepassword-passwordhash)
* [Migrating from v1](#migrating-from-v1)
* [Installation](#installation)
* [Tests](#tests)
* [LICENSE](#license)

<!-- toc! -->

## Example

Generate new password hash

```js
import passwordHash from 'pbkdf2-password-hash'

// generates random salt
passwordHash.hash('password')
  .then((hash) => {
    //> hash === 'sha512$120000$64$hBKkXNgl006VdFvQPyCawVYwdT78Uns1x0VnixvHHKfVzjS0Y0p58auWZ5AVV6MFGt/E1HaJ2MOqJSlKkaDspA==$zkq/ubSJoqflS23Ot5EkI6H+LE+D26p+6C0wtPHIr4HPVZPfXR/ZiflXAQ01b2uXCfHN8XUzOXWY9MqcvBYIog=='
  })
```

Generate password hash with different options

```js
passwordHash.hash('password', {iterations: 100, digest: 'sha1', keylen: 16, saltlen: 16})
.then((hash) => {
  //> hash === 'sha1$100$16$fwzPKhZjCQSZMz+hY7A29A==$KdGdduxkKd08FDUuUVDVRQ=='
})
```

Validate password hash

```js
const hash = 'sha512$120000$64$hBKkXNgl006VdFvQPyCawVYwdT78Uns1x0VnixvHHKfVzjS0Y0p58auWZ5AVV6MFGt/E1HaJ2MOqJSlKkaDspA==$zkq/ubSJoqflS23Ot5EkI6H+LE+D26p+6C0wtPHIr4HPVZPfXR/ZiflXAQ01b2uXCfHN8XUzOXWY9MqcvBYIog=='
passwordHash.compare('password', hash)
.then((isValid) => {
  //> isValid === true
})
```

## API

### `hash(password, [salt], [opts])`

Generate a new password hash for password using PBKDF2.
Safety is obtained by using safe digest, large number of iterations and large key-length for PBKDF2

**Parameters**

| parameter                  | type   | description                                         |
| -------------------------- | ------ | --------------------------------------------------- |
| `password`                 | String |                                                     |
| `[salt]`                   | String | _optional:_ salt                           |
| `[opts.iterations=120000]` | Number | _optional:_ PBKDF2 number of iterations (~10 hashes/sec @ 2GHz) |
| `[opts.digest=sha512]`     | String | _optional:_ PBKDF2 digest                           |
| `[opts.keylen=64]`         | Number | _optional:_ PBKDF2 key length                       |
| `[opts.saltlen=64]`        | Number | _optional:_ salt length in case salt is not defined |


**Returns** `Promise`, hashed password in `<digest>$<iterations>$<keylen>$<salt>$<hash>` notation

### `compare(password, passwordHash)`

validate password against passwordHash

**Parameters**

| parameter      | type   | description         |
| -------------- | ------ | ------------------- |
| `password`     | String | plain-text password |
| `passwordHash` | String | hashed password     |


**Returns** `Promise`, true if hash matches password

## Installation

Requires [nodejs](http://nodejs.org/) >= v6.0.0

```sh
$ npm install --save pbkdf2-password-hash
```

## Tests

```sh
$ npm test
```

## LICENSE

UNLICENSE <https://unlicense.org>
