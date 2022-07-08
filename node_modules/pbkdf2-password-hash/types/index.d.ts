export namespace passwordHash {
    export { hash };
    export { compare };
}
export default passwordHash;
/**
* Generate a new password hash for `password` using PBKDF2
* Safety is obtained by large number of iterations and large key length for PBKDF2
* @param {String} password
* @param {String} [salt] - optional salt
* @param {Object} [opts]
* @param {Number} [opts.iterations=120000] - PBKDF2 number of iterations (~10 hashes/sec @ 2GHz)
* @param {String} [opts.digest=sha512] - PBKDF2 digest
* @param {Number} [opts.keylen=64] - PBKDF2 key length
* @param {Number} [opts.saltlen=64] - salt length in case `salt` is not defined
* @return {Promise} hashed password in `<digest>$<iterations>$<keylen>$<salt>$<hash>` notation
*/
declare function hash(password: string, salt?: string | undefined, opts?: {
    iterations?: number | undefined;
    digest?: string | undefined;
    keylen?: number | undefined;
    saltlen?: number | undefined;
} | undefined): Promise<any>;
/**
* validate `password` against `passwordHash`
* @param {String} password - plain-text password
* @param {String} passwordHash - hashed password
* @return {Promise} true if hash matches password
*/
declare function compare(password: string, passwordHash: string): Promise<any>;
