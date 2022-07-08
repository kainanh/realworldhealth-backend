export default timingSafeEqual;
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
declare function timingSafeEqual(a: string | Buffer, b: string | Buffer): boolean;
