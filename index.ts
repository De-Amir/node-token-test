import { resolve } from "url";

// sign with RSA SHA256
const fs = require('fs')
const request = require('request')
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const _userToken = fs.readFileSync('user.token');
const _jwks_uri = fs.readFileSync('jwks_uri.json');
const iss = 'https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_MUQxpBk7p'
const context = { fail: (error) => { console.log('Context:  ' + error) } }
const getMessageToken = async (userToken, botId) => {
    const user = await verifyUserToken(userToken);
    if (user) {
        const message = { text: 'Message text', creationDate: 135165 }
        console.log('------------------------------------');
        console.log(user);
        console.log('------------------------------------');
        const { userId } = user as any

        return createMessageToken(userId, botId, message)

    }
}

/**
 * User Claim Class
 */
class UserCliam {
    constructor(
        public username: string,
        public company: string,
        public customerName: string,
        public userRole: string,
        public email: string,
        public avatar: string,
    ) {
    }
}


/**
 * Validate user token 
 */
const validateToken = (token, pems, context) => {
    //Fail if the token is not jwt
    var decodedJwt = jwt.decode(token, { complete: true });
    if (!decodedJwt) {
        console.log("Not a valid JWT token");
        throw new Error("Unauthorized");
    }

    //Fail if token is not from your User Pool
    if (decodedJwt.payload.iss != iss) {
        console.log("invalid issuer");
        throw new Error("Unauthorized");
    }

    //Reject the jwt if it's not an 'Access Token'
    if (decodedJwt.payload.token_use != 'id') {
        console.log("Not an access token");
        throw new Error("Unauthorized");
    }

    //Get the kid from the token and retrieve corresponding PEM
    var kid = decodedJwt.header.kid;
    var pem = pems[kid];

    if (!pem) {
        console.log('Invalid access token');
        throw new Error("Unauthorized");
    }

    //Verify the signature of the JWT token to ensure it's really coming from your User Pool
    try {
        const payload = jwt.verify(String(token), pem, { issuer: iss })

        var principalId = payload.sub;

        console.log('SUCCESS :  ' + principalId, payload)
        const userClaim = new UserCliam(
            payload['cognito:username'],
            payload['Company'],
            payload['customerName'],
            payload['userType'],
            payload['email'],
            payload['avatar'],
        );
        console.log('USER CLAIM:   ', userClaim)
        return userClaim
    } catch (error) {
        throw new Error("Unauthorized" + ':  ' + error);
    }
};


/**
 * Verify user token
 */
const verifyUserToken = (userToken) => {
    return new Promise<UserCliam>((resolve, reject) => {
        let pems;
        let user;
        if (!pems) {
            request({
                url: iss + '/.well-known/jwks.json',
                json: true
            }, function (error, response, body) {
                if (!error && response.statusCode === 200) {
                    pems = {};
                    let keys = body['keys'];
                    for (let i = 0; i < keys.length; i++) {
                        //Convert each key to PEM
                        let key_id = keys[i].kid;
                        let modulus = keys[i].n;
                        let exponent = keys[i].e;
                        let key_type = keys[i].kty;
                        let jwk = { kty: key_type, n: modulus, e: exponent };
                        let pem = jwkToPem(jwk);
                        pems[key_id] = pem;
                    }
                    //Now continue with validating the token
                    try {

                        user = validateToken(userToken, pems, context);
                        resolve(user)
                    } catch (error) {
                        console.error('error: ', error)
                        reject(error)
                    }
                } else {
                    //Unable to download JWKs, fail the call
                    context.fail("error");
                    reject('Unable to download JWKs, fail the call')
                }
            });
        } else {
            //PEMs are already downloaded, continue with validating the token
            user = validateToken(userToken, pems, context);
            resolve(user)
        };
        console.log('USER:  ', user)

    })
}

/**
 * Create message token 
 */
const createMessageToken = (userId, botId, message) => {
    const cert = fs.readFileSync('private.key');
    const token = jwt.sign({ ...message, userId, botId }, cert, { algorithm: 'RS256' });
    return token;
}

/**
 * Verify message token
 */
const verifyMessageToken = (token) => {
    var cert = fs.readFileSync('public.key');  // get public key
    jwt.verify(token, cert, function (err, decoded) {
        
    console.log('------------- Decoded -----------------------');
    console.log(decoded);
    console.log('------------------------------------');
    });
}

getMessageToken(_userToken, '4c54ff4b-c8f9-4d67-8ebe-eaa7170b5a45').then((messageToken) => {

    console.log('------------- Token ----------------------');
    console.log(messageToken);
    console.log('------------------------------------');

    verifyMessageToken(messageToken)
})
