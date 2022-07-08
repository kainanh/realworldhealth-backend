'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var crypto = require('crypto');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);

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
  const isEqual = crypto__default["default"].timingSafeEqual(toHash(a), toHash(b));
  // make final check to detect hash collisions
  return (isEqual && a.toString() === b.toString())
}

const toHash = (str) => crypto__default["default"].createHash('sha256').update(str).digest();

exports["default"] = timingSafeEqual;
module.exports = exports["default"];
