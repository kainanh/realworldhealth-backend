export default timingSafeEqual;
/**
 * string, buffer comparison in length-constant time
 * @see https://codahale.com/a-lesson-in-timing-attacks/
 *
 * @param {string|Uint8Array} a - string or buffer from input
 * @param {string|Uint8Array} b - string or buffer to compare with `a`
 * @return {boolean} true if strings match
 */
declare function timingSafeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean;
