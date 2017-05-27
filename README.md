This is a demonstration authentication system written for The Engine Company.

## Installation

To setup the project as-is, you will need the following:

* Node.js
* MongoDB

Installation Process:

1. Pull the repo down
2. From a node command prompt, type npm install
3. In the database.js file, set the database pointers to active databases in your MongoDB
4. From a node command prompt, type nodemon server.js to start the server
5. Navigate to localhost:8080

## Features

* Authentication using passport.js
* Optional two factor authentication using passport-totp and Google Authenticator
* Rate limiting to prevent DDOS using express-rate-limit
* Failed login lockout based on username and IP address
* In-profile and anonymous password resetting
* Cluster-friendly persistent client state using connect-mongodb-session

## Notes

You can swap the MongoDB and the TinyCache for whatever databases you want by modifying the DB access in user-control.js and email-control.js.

There is no actual email service setup currently, just console logging for email actions.