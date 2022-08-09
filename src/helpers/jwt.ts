import jwt from "jsonwebtoken";

/**
 * @param {any} data Data to be signed
 * @param {jwt.Secret} secret Secret key
 * @param {string|number} expiredIn Time for token to be expired in second or timespan. Eg: 60, "2 days", "10h", "7d".
 * @returns {Promise<string>} Return a promise of string token
 */
export function createToken(data: any, secret: jwt.Secret, expiredIn: string | number = "30d"): Promise<string> {
    return new Promise((resolve, reject) => {
        jwt.sign(
            { ...data },
            secret,
            {
                algorithm: "HS256",
                expiresIn: expiredIn,
            },
            (err, token) => {
                if (err || !token) return reject(err);
                resolve(token);
            }
        );
    });
}

/**
 * @param {string} token Token
 * @param {jwt.Secret} secret Secret key
 * @returns {Promise<any>} Return a promise of data from token
 */
export function authenticate(token: string, secret: jwt.Secret): Promise<any> {
    return new Promise((resolve, reject) => {
        jwt.verify(token, secret, (err, decoded) => {
            if (err) return reject(err);
            resolve(decoded);
        });
    });
}
