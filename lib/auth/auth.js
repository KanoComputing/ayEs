/*
	ayes/auth/auth.js
	authorization (not authentication)
*/

const JWT = require('jsonwebtoken');

const ERROR = require('../error');

const RESPOND = require('../respond');

const Auth = function Auth(secretOrPublicKey, options = {}) {
	const { alg, logger } = options;
	
	if (secretOrPublicKey.indexOf('BEGIN PUBLIC KEY') !== -1) {
	    this.algorithm = alg || 'ES256';
	} else {
	    this.algorithm = alg || 'HS256';
	}
	
	this.Logger = logger || console;

	if (!secretOrPublicKey) {
		const error = new Error(null, 'JWT_SECRET not supplied.');
		this.Logger.error(error);
		throw error;
	}
	this._JWT_secretOrPublicKey = secretOrPublicKey;
	this.generateAuthMiddleWare = function generateAuthMiddleWare() {
		return function amw(req, res, next) {
			let dtoken;
			let token;

			try {
				token = Auth.parseAuthHeaders(req.headers);
			} catch (e) {
				return RESPOND.notAuthorized(res, req, e);
			}

			try {
				dtoken = Auth.decodeJWT(token, this._JWT_secretOrPublicKey);
			} catch (e) {
				const err = Auth.decodeErr(e);
				switch (true) {
					case (err instanceof ERROR.AuthError):
						return RESPOND.notAuthorized(res, req, err);
					default:
						return RESPOND.serverError(res, req, err);
				}
			}

			req.dtoken = dtoken;
			return next();
		}.bind(this);
	}.bind(this);
};

Auth.decodeErr = function decodeErr(error) {
	switch (error.message) {
		case 'Algorithm not supported':
			return new ERROR.AuthError('JWT algorithm not supported', ERROR.codes.JWT_UNSUPPORTED_ALGORITHM);
		case 'Token not yet active':
			return new ERROR.AuthError('Token not yet active', ERROR.codes.JWT_TOKEN_NOT_ACTIVE);
		case 'Token expired':
			return new ERROR.AuthError('Token expired', ERROR.codes.JWT_TOKEN_EXPIRED);
		case 'Signature verification failed':
			return new ERROR.AuthError('Signature verification failed', ERROR.codes.JWT_SIG_VERIFY_FAILED);
		default:
			if (error.message.indexOf('Unexpected token') !== -1) {
				return new ERROR.AuthError('Token corrupted', ERROR.codes.JWT_CORRUPT);
			}
			return new ERROR.ServerError(error, error.message, ERROR.codes.SERVER_ERROR);
	}
};

Auth.decodeJWT = function decodeJWT(jwt, secretOrPublicKey) {
	if (secretOrPublicKey.indexOf('BEGIN PUBLIC KEY') !== -1) {
		return JWT.verify(jwt, secretOrPublicKey, { algorithm: Auth.algorithm || 'ES256' });
	} else {
		return JWT.verify(jwt, secretOrPublicKey, { algorithm: Auth.algorithm || 'HS256' });
	}
};

Auth.encodeJWT = function encodeJWT(payload, secret) {
	if (secret.indexOf('BEGIN EC PRIVATE KEY') !== -1) {
		return JWT.sign(payload, secret, { algorithm: Auth.algorithm || 'ES256' });
	} else {
		return JWT.sign(payload, secret, { algorithm: Auth.algorithm || 'HS256' });
	}
};

Auth.parseAuthHeaders = function parseAuthHeaders(headers) {
	if (headers && headers.authorization) {
		const parts = headers.authorization.split(' ');
		if (parts.length === 2) {
			const scheme = parts[0];
			const credentials = parts[1];
			if (/^Bearer$/i.test(scheme)) {
				return credentials;
			}
			/* else */
			throw new ERROR.AuthError(
				'Format is Authorization: Bearer [token]',
				ERROR.codes.JWT_CREDS_BAD_SCHEME
			);
		} else {
			throw new ERROR.AuthError(
				'Format is Authorization: Bearer [token]',
				ERROR.codes.JWT_CREDS_BAD_FORMAT
			);
		}
	} else {
		throw new ERROR.AuthError(
			'JWT Authorization is required',
			ERROR.codes.JWT_CREDS_REQUIRED
		);
	}
};

module.exports = Auth;
