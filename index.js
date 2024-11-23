const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

/**
 * Generate a JWT token
 * @param {Object} payload - The data to include in the token
 * @param {String} secret - The JWT secret key
 * @param {Object} options - Additional options like expiresIn
 * @returns {String} - The generated JWT token
 */
function generateToken(payload, secret, options = { expiresIn: '1h' }) {
  return jwt.sign(payload, secret, options);
}

/**
 * Verify a JWT token
 * @param {String} token - The JWT token
 * @param {String} secret - The JWT secret key
 * @returns {Object} - The decoded token
 */
function verifyToken(token, secret) {
  return jwt.verify(token, secret);
}

/**
 * Hash a password
 * @param {String} password - The plain text password
 * @returns {String} - The hashed password
 */
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

/**
 * Compare a password with its hashed version
 * @param {String} password - The plain text password
 * @param {String} hashedPassword - The hashed password
 * @returns {Boolean} - Whether the passwords match
 */
async function comparePassword(password, hashedPassword) {
  return bcrypt.compare(password, hashedPassword);
}

/**
 * Create a standardized API response
 * @param {Boolean} success - Whether the operation was successful
 * @param {String} message - A message describing the response
 * @param {Object} data - The data to return in the response
 * @returns {Object} - The standardized API response object
 */
function createApiResponse(success, message, data = null) {
  return { success, message, data };
}

module.exports = {
  generateToken,
  verifyToken,
  hashPassword,
  comparePassword,
  createApiResponse,
};
