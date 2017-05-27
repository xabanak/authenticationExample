// load all the things we need
var LocalStrategy = require('passport-local').Strategy;
var TotpStrategy = require('passport-totp').Strategy;
var base32 = require('thirty-two');
var userControl = require('../app/user-control.js');
var emailControl = require('../app/email-control');

module.exports = function(passport) {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        userControl.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, email, password, done) {
        if (email)
            email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching
        
        // asynchronous
        process.nextTick(function() {

            if (userControl.checkUserLockout(email) || userControl.checkUserLockout(req.connection.remoteAddress))
            {
                return done(null, false, req.flash('loginMessage', 'You are currently locked out.'))
            }
            
            userControl.validateUser(function(err, user, options){
                if (userControl.checkUserLockout(user.email))
                {
                    emailControl.sendLockedAccountEmail(user.email, req.connection.remoteAddress);
                }
                return done(err, user, options);
            }, req, email, password)
        });

    }));

    passport.use(new TotpStrategy(
    function(user, done) {
        var key = user.key;
        if(!key) {
            return done(new Error('No key'));
        } else {
            return done(null, base32.decode(key), 30); //30 = valid key period
        }
    })
    );

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
    function(req, email, password, done) {
        if (email)
            email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

        // asynchronous
        process.nextTick(function() {

            if (userControl.checkUserLockout(req.connection.remoteAddress))
            {
                return done(null, false, req.flash('signupMessage', 'You are currently locked out.'));
            }

            if (!emailControl.checkEmailValidity(email))
            {
                return done(null, false, req.flash('signupMessage', 'Please enter a valid e-mail.'));
            }

            // if the user is not already logged in:
            if (!req.user) {
                userControl.createUser(done, req, email, password);

            }
            // if the user is already logged in
            else 
            {
                return done(null, req.user);
            }
        });
    }));
};