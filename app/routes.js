// routes.js

module.exports = function(app, passport) {
    var base32 = require('thirty-two');
    var sprintf = require('sprintf');
    var crypto = require('crypto');
    var strings = require('../views/strings.json');
    var userControl = require('./user-control.js');
    var emailControl = require('./email-control.js');

// normal routes ===============================================================

    // show the home page (will also have our login links)
    app.get('/', function(req, res) {
        res.render('index.ejs');
    });

    // PROFILE SECTION =========================
    app.get('/profile', hasAuthenticated, ensureTotp, function(req, res) {
        res.render('profile.ejs', {
            user : req.user
        });
    });

    // LOGOUT ==============================
    app.get('/logout', function(req, res) {
        if (req._passport.session)
            req._passport.session.has2fa = false;
        req.logout();
        res.redirect('/');
    });

// =============================================================================
// AUTHENTICATE (FIRST LOGIN) ==================================================
// =============================================================================

    // locally --------------------------------
        // LOGIN ===============================
        // show the login form
        app.get('/login', hasNotAuthenticated, function(req, res) {
                res.render('login.ejs', { message: req.flash('loginMessage') });
        });
 
        // process the login form
        app.post('/login', passport.authenticate('local-login', {
            failureRedirect : '/login', // redirect back to the signup page if there is an error
            failureFlash : true // allow flash messages
        }),  function(req, res) {
        if(req.user.key) {
            req.session.method = 'totp';
            res.redirect('/totp-input');
            return;
        } else {
            req.session.method = 'plain';
            res.redirect('/profile');
        } 
    });

        // SIGNUP =================================
        // show the signup form
        app.get('/signup', hasNotAuthenticated, function(req, res) {
                res.render('signup.ejs', { message: req.flash('signupMessage') });
        });

        // process the signup form
        app.post('/signup', passport.authenticate('local-signup', { // redirect to the secure profile section
            failureRedirect : '/signup', // redirect back to the signup page if there is an error
            failureFlash : true
        }), function(req, res) {
        if(req.user.key) {
            req.session.method = 'totp';
            res.redirect('/totp-input');
            return;
        } else {
            req.session.method = 'plain';
            res.redirect('/profile');
        }
    });

// =============================================================================
// TOTP HANDLING =============================================================
// =============================================================================
// Used to handle TOTP input and setup stuff

    app.get('/totp-input', isLoggedIn, function(req, res) {
        if(!req.user.key) {
            res.redirect('/login');
            return;
        }    
        res.render('totp-input');
    });

    app.post('/totp-input', isLoggedIn, passport.authenticate('totp', {
        failureRedirect: '/login',
        successRedirect: '/profile'
    }));

    app.get('/totp-setup', 
        hasAuthenticated,
        ensureTotp,
        function(req, res) {
            if (!req.user.key)
            {
                var url = null;
                req.session.method = 'totp';
                var secret = base32.encode(crypto.randomBytes(16));
                //Discard equal signs (part of base32, 
                //not required by Google Authenticator)
                //Base32 encoding is required by Google Authenticator. 
                //Other applications
                //may place other restrictions on the shared key format.
                secret = secret.toString().replace(/=/g, '');
                req.user.key = secret;
                req.user.save();
                var qrData = sprintf('otpauth://totp/%s?secret=%s', 
                                    req.user.email, req.user.key);
                    url = "https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=" + 
                        qrData;

                res.render('totp-setup.ejs', {
                    user : req.user,
                    qrUrl: url
                });
            }
            else
            {
                res.redirect('/profile');
            }
        }
    );

    app.post('/totp-setup',
        hasAuthenticated,
        ensureTotp,
        function(req, res) {        
            res.redirect('/profile');
        }      
    );

    app.get('/totp-disable', hasAuthenticated, function(req, res) {
        if(!req.user.key) {
            res.redirect('/login');
            return;
        }    
        res.render('totp-disable', {
            strings: strings
        });
    });

    app.post('/totp-disable', hasAuthenticated, hasAuthenticated, function(req, res){
        if(req.user.key)
        {
            req.user.key = null;
            req.user.save();
            req.session.method = 'plain';
            req._passport.session.has2fa = false;
        }
        res.redirect('/profile');
    }); 

    app.get('/forgot', function(req, res) {
        res.render('forgot', 
        { message: req.flash('forgotMessage') }
        );
    });

    app.get('/reset/:token', function(req, res) {
        userControl.findOne({ pwResetToken: req.params.token, pwResetTokenExp: { $gt: Date.now() } }, function(err, user) {
            if (!user) {
                req.flash('resetMessage', 'Password reset token is invalid or has expired.');
                return res.redirect('/forgot');
            }
            res.render('reset',         
            { message: req.flash('resetMessage'),
                token: req.params.token });
        });
    });

    app.post('/reset/:token', function(req, res) {
        emailControl.validatePasswordReset(req, res, false);
        req.logout();
    });

    app.post('/forgot', function(req, res, next) {
        emailControl.sendPasswordResetEmail(req, res, next);
    });

     app.get('/reset', hasAuthenticated, function(req, res) {
        res.render('reset',         
        { message: req.flash('resetMessage'),
            token: req.params.token 
        });
    });

    app.post('/reset', hasAuthenticated, function(req, res) {
        emailControl.validatePasswordReset(req, res, true);
        req.logout();
    });

};

// route middleware to ensure user is logged in
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated())
    {
        if (!req._passport.session.has2fa)
        {
            return next();
        }
        else
        {
            res.redirect('/profile');
            return;
        }
    }
    res.redirect('/');
}

// route middleware to ensure user is logged in and second factor authenticated
function hasAuthenticated(req, res, next)
{
    if (req.isAuthenticated())
    {
        if (req._passport.session.has2fa == true || !req.user.key)
        {
            return next();
        }
        else
        {
            res.redirect('/totp-input');
            return;
        }
    }
    else
    {
        res.redirect('/');
        return;
    }
}

// route middleware to ensure user hasn't logged to allow access to login/signup pages
function hasNotAuthenticated(req, res, next)
{
    if (req.isAuthenticated())
    {
        if (req._passport.session.has2fa == true || !req.user.key)
        {
            res.redirect('/profile');
            return;
        }
        else
        {
            res.redirect('/totp-input');
            return;
        }
    }
    else
    {
        return next();
    }
}

// routing middleware to ensure the session is correct for the type of user
function ensureTotp(req, res, next) {
    if((req.user.key && req.session.method == 'totp') ||
       (!req.user.key && req.session.method == 'plain')) {
        next();
    } else {
        res.redirect('/login');
    }
}
