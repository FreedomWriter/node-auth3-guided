# Drawbacks to sessions

- scalabitly (horizontal scalability)
- security
- managing sessions is difficult
- can be slow

# [JWT](https://jwt.io/)

# Authentication implementation

- completely stateless and self contained
- becoming industry standard
- they come with their own drawbacks

A JWT contains 3 parts:

Header:

{
"alg": "HS256",
"typ": "JWT"
}

Payload:

{
"userId": 1,
"role": "admin"
"iat": 1560203144,
"exp": 1560206744
}

Signature:

HMACSHA256(
base64UrlEncode(header) + "." +
base64UrlEncode(payload),

your-256-bit-secret

) secret base64 encoded

1. A header (metadata for token)
   1. "alg" - algorythm used to sign the token
   2. "typ" - type
2. Payload
   1. custom information specific to authorization
   2. This is where you can store info about user
   3. "iat" issued at timestamp for when token was created
   4. "exp" expires at timestamp for when token expires
   5. should never hold sensitve data, can be decoded on the client side since it is only stored in base64
3. Signature

   1. First two parts of the token concatanated together along with a secret string (an encryption key) - each peice hashed

Session read from memory to see if user is validated, JWTs read the token.

- an upside to using JWTs is that JWTs (being stateless) are faster, they don't have to look up sessions anywhere - if the signature is valid, the session is valid
- if you were horizontally scaling you wouldn't have to have a shared memory, where as if you were using sessions, you would need it because each session would have to be able to look up if the users session was valid.

Downsides to JWTs (stateless authentication)

- no history

  - no way to logout a user. (imagine a user who was abusing your system, all you could do is hope you had set an expiration and wait for the toke to expire. Once a user has a valid token, that token is valid) The only way you could block a user is by storing tokens in a db, and create a "black list" of tokens that have been logged out and if the token exists in the blacklist when the user is trying to authorize, the user is denied. But if you are storing in a db, you may as well use sessions

  IN THE EVENT OF A MAJOR SECURITY THREAT - you could change the secret key which would invalidate all tokens, all users would have to log back in.

JWTs and Session Cookies together: - think through this implementation more.
misc: session are server side, cookies are client side - if you store it in a cookie, it's going to get eaten.

- you could store the JWT in the session cookie, but this is redundant.
- if you wanted to use JWT and sessions, you could store the session cookie in the JWT. For instance instead of storing the userID in the payload, you would store the SID, if you wanted to validate a users role before they access anything (before the session validation happens) then you would be able to validate the token before you look up the token.

1.  Install json web tokens library
    `npm i jsonwebtoken`
2.  In authRouter
    const jwt = require("jsonwebtoken")
3.  New /login router - sends token back
    router.post("/login", (req, res) => {
    let { username, password } = req.body;

        Users.findBy({ username })
            .first()
            .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                jwt.sign(
                {
                    userId: user.id
                },
                "super secret string",
                (err, token) => {
                    if (err) {
                    res.status(401).json({ message: "Could not generate token" });
                    } else {
                    res.status(200).json({
                        message: `Welcome ${user.username}!`,
                        authToken: token
                    });
                    }
                }
                );
            } else {
                res.status(401).json({ message: "Invalid Credentials" });
            }
            })
            .catch(error => {
            res.status(500).json(error);
            });

    });

    The relevant code that was added:

        jwt.sign(
            {
                userId: user.id
            },
            "super secret string",
            {
                expiresIn: "1h"
            }, //1h = 1 hour
            (err, token) => {
                if (err) {
                res
                    .status(401)
                    .json({
                    message: "Could not generate token",
                    error: err.message
                    });
                } else {
                res.status(200).json({
                    message: `Welcome ${user.username}!`,
                    authToken: token
                });
                }
            }
        );

Clean that code up by creating a generateToken function:

    function generateToken(user) {
        return jwt.sign(
            {
            userId: user.id
            },
            "super secret string",
            {
            expiresIn: "1h"
            } //1h = 1 hour
        );
    }

    now the login router would look like this:

    router.post("/login", (req, res) => {
        let { username, password } = req.body;

        Users.findBy({ username })
            .first()
            .then(user => {
            if (user && bcrypt.compareSync(password, user.password)) {
                generateToken(user);
                res.status(200).json({
                message: `Welcome ${user.username}`,
                authToken: generateToken
                });
            } else {
                res.status(401).json({ message: "Invalid Credentials" });
            }
            })
            .catch(error => {
            res.status(500).json(error);
            });
    });

return token on "/register" - now you don't have to login after you register

    router.post("/register", (req, res) => {
    let user = req.body;
    const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
    user.password = hash;

    Users.add(user)
        .then(saved => {
        const token = generateToken(saved);
        res.status(201).json({
          message: `Welcome ${user.username}`,
          authToken: token
        });
        })
        .catch(error => {
        res.status(500).json(error);
        });
    });

We need to hide our 'super secret string' for security's sake

1. Create a `.env` file (at the root of the project)
   1. will need `npm i dotenv`
   2. JWT_SECRET = "super secret string"
2. require in index.js (so it is available to our whole app - index.js is the entrypoint)
   1. require('dotenv).config();
3. Can also:
   1. Create a `config` directory
   2. create a secrets.js file
      1. module.exports = {
         jwtSecret: process.env.JWT_SECRET
         };
   3. in router sending using generateToken()
      1. const secrets = require("../config/secrets");
      2. function generateToken(user) {
         return jwt.sign(
         {
         userId: user.id
         },
         secrets.jwt,
         {
         expiresIn: "1h"
         } //1h = 1 hour
         );
         }

# Authorization implementation

In Restricted Middleware:

    File now becomes:

    const secrets = require("../config/secrets");
    const jwt = require("jsonwebtoken");

    module.exports = (req, res, next) => {
    const token = req.headers.authorization;

    if (token) {
        jwt.verify(token, secrets.jwt, (err, payload) => {
        if (err) {
            res.status(403).json({ message: "You are not authorized" });
        } else {
            req.userId = payload.userId;
            next();
        }
        });
    } else {
        res.status(400).json({ message: "No credentials provided" });
    }
    };

# Add permissions level to user

    function generateToken(user) {
        return jwt.sign(
            {
            userId: user.id,
            userRole: "student",
            },
            "super secret string",
            {
            expiresIn: "1h"
            } //1h = 1 hour
        );
    }

In Restricted middleware:

    const secrets = require("../config/secrets");
    const jwt = require("jsonwebtoken");

    module.exports = (role) => {
        return (req, res, next) => {
            const token = req.headers.authorization;

            if (token) {
                jwt.verify(token, secrets.jwt, (err, payload) => {
                if (err) {
                    res.status(403).json({ message: "You are not authorized" });
                } else {
                    if ( role !== payload.userRole) {
                        res.status(403).json({
                            message: "You are not do not have permission for this endpoint."
                        })
                    } else {
                        req.userId = payload.userId
                        next()
                    }
                }
                });
            } else {
                res.status(400).json({ message: "No credentials provided" });
            }
        }
    };

Where you are using restricted middleware

- restricted('student')
- using restricted like this would mean that this route was only available to students.
