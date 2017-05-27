// user-control.js

var TinyCache = require('tinycache');
var base32 = require('thirty-two');

// load up the user model
var User = require('../app/models/user');

var cache = new TinyCache();

MAX_LOGIN_FAILURES = 5;
LOCKOUT_TIME_MS = 1000 * 60 * 15; // 15 minute lockout in ms

module.exports = userControl = 
{
    updateUserLockout : function(valueToCheck)
    {
        var timeoutEntry = cache.get(valueToCheck);
        if (timeoutEntry == null)
        {
            cache.put(valueToCheck, 1);
            cache.put(valueToCheck + 'timestamp', Date.now());
        }
        else
        {
            cache.put(valueToCheck, timeoutEntry+1);
        }
    },

    checkUserLockout : function(valueToCheck)
    { 
        var lockedOut = false;
        var timeoutEntry = cache.get(valueToCheck);
        var timeoutEntryTimestamp = cache.get(valueToCheck + 'timestamp');
        if (timeoutEntry == null)
        {
            lockedOut = false;
        }
        else if (timeoutEntryTimestamp != null)
        {
            if (timeoutEntry >= MAX_LOGIN_FAILURES && Date.now() - timeoutEntryTimestamp > LOCKOUT_TIME_MS)
            {
                cache.del(valueToCheck);
                cache.del(valueToCheck + 'timestamp');
                lockedOut = false;
            }
            else if (timeoutEntry < MAX_LOGIN_FAILURES)
            {
                lockedOut = false;
            }
            else
            {
                lockedOut = true;
            }
        }
        else
        {
            // TODO: This shouldn't happen. worry?
        }
        return lockedOut;
    },

    validateUser : function(done, req, email, password)
    {
        var self = this;
        User.findOne({ 'email' :  email }, function(err, user) 
        {
            // if there are any errors, return the error
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
            {
                console.log("Only adding ip");
                self.updateUserLockout(req.connection.remoteAddress);
                return done(null, false, req.flash('loginMessage', 'Incorrect username or password.'));                 
            }

            if (!user.validPassword(password))
            {
                console.log("adding IP and username");
                self.updateUserLockout(req.connection.remoteAddress);
                self.updateUserLockout(user.email);
                return done(null, false, req.flash('loginMessage', 'Incorrect username or password.'));
            }

            // all is well, return user
            else
                return done(null, user);
        });
    },

    createUser : function(done, req, email, password)
    {
        var self = this;
        User.findOne({ 'email' :  email }, function(err, user) 
        {
            // if there are any errors, return the error
            if (err)
                return done(err);

            // check to see if theres already a user with that email
            if (user) 
            {
                return done(null, false, req.flash('signupMessage', 'That username is already taken.'));
            } 
            // create the user
            else 
            {
                var newUser = new User();

                newUser.email = email;
                newUser.password = newUser.generateHash(password);

                newUser.save(function(err) 
                {
                    if (err)
                    {
                        return done(err);
                    }
                    return done(null, newUser);
                });
            }
        });
    },

    findById : function(id, callback)
    {
        User.findById(id, callback);
    },

    findOne : function(value, callback)
    {
        User.findOne(value, callback);
    }
}