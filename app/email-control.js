// email-control.js

/* pwResetToken : String,
    pwResetTokenExp: Number,
    verifyToken  : String,
    verifyTokenExp: Number*/

var crypto = require('crypto');
var userControl = require('./user-control');
var async = require('async');

module.exports = emailControl = 
{
    checkEmailValidity : function(email)
    {
        // do something to check email
        var re = /\S+@\S+\.\S+/;
        return re.test(email);
    },

    sendLockedAccountEmail : function(email, sourceIp)
    {
        // Send an email to notify this account has been locked, provide the IP that locked it.
        console.log("Account locked out!");
        console.log("Account email: " + email);
        console.log("Source IP for lockout: " + sourceIp);
    },

    sendPasswordResetEmail : function(req, res, next)
    {
        // Send an email with a magic link to reset the user password
        async.waterfall([
        function(done) {
            crypto.randomBytes(20, function(err, buf) {
            var token = buf.toString('hex');
            done(err, token);
            });
        },
        function(token, done) {
            userControl.findOne({ email : req.body.email }, function(err, user) {
                if (!user) {
                    req.flash('forgotMessage', 'Invalid email address.');
                    return res.redirect('/reset');
                }

                user.pwResetToken = token;
                user.pwResetTokenExp = Date.now() + 1000 * 60 * 60; // Expires an hour after generation

                user.save(function(err) {
                    done(err, token, user);
                });
            });
        },
        function(token, user, done) {
            // Handle sending reset email with this information here
            console.log("PASSWORD RESET TOGGLED");
            console.log("Email: " + user.email);
            console.log("Unique reset URL: " + 'http://' + req.headers.host + '/reset/' + token);
            req.flash('forgotMessage', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
            done();
        }
        ], function(err) {
            if (err) return next(err);
                res.redirect('/forgot');
        });
    },

    validatePasswordReset : function(req, res, secureReset)
    {
        // Send an email to the user to notify that the password has been changed
        async.waterfall([
        function(done) {
            if (!secureReset)
            {
                userControl.findOne({ pwResetToken: req.params.token}, function(err, user) {
                    if (!user || user.pwResetTokenExp < Date.now()) {
                        req.flash('resetMessage', 'Password reset token is invalid or has expired.');
                        return res.redirect('back');
                    }
           
                    user.password = user.generateHash(req.body.password);
                    user.pwResetToken = undefined;
                    user.pwResetTokenExp = undefined;

                    user.save();
                    done(user);
                });
            }
            else
            {
                req.user.password = req.user.generateHash(req.body.password);  
                req.user.save();
                done(req.user);
            }
        },
        function(user, done) {
            // Handle sending password change email with this information here
            console.log("PASSWORD CHANGED");
            console.log("Email: " + user.email);
            req.flash('resetMessage', 'Success! Your password has been changed.');
            req.logout();
            done();
        }
    ], function() {
        if (secureReset)
        {
            res.redirect('/profile');
        }
        else
        {
            res.redirect('/');
        }
    });
    },

    sendVerificationEmail : function(email)
    {
        // Send an email with a magic link to verify a new account
    }
}