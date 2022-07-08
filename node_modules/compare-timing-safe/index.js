import crypto from 'crypto'

/**
 * string, buffer comparison in length-constant time
 * uses crypto module
 * @see https://codahale.com/a-lesson-in-timing-attacks/
 *
 * @param {String|Buffer} a - string or buffer from input
 * @param {String|Buffer} b - string or buffer to compare with `a`
 * @return {Boolean} true if strings match
 * @example
 * const timingSafeEqual = require('compare-timing-safe')
 * const input = 'a'
 * const compareWith = 'bbbbbbbb'
 * timingSafeEqual(input, compareWith)
 * //> false
 */
function timingSafeEqual (a, b) {
  if (!a || !a.length || !b || !b.length) {
    return false
  }
  const isEqual = crypto.timingSafeEqual(toHash(a), toHash(b))
  // make final check to detect hash collisions
  return (isEqual && a.toString() === b.toString())
}

const toHash = (str) => crypto.createHash('sha256').update(str).digest()

export default timingSafeEqual
