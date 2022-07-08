const SEP = '$'

function convert (passwordHash) {
  let [digest, iterations, keylen, salt, hash] = passwordHash.split(SEP)
  salt = Buffer.from(salt).toString('base64')
  const newPasswordHash = [digest, iterations, keylen, salt, hash].join(SEP)
  return newPasswordHash
}

export default convert
