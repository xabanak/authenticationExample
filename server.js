// server.js

// set up ======================================================================
// get all the tools we need
var express  = require('express');
var app      = express();
var port     = process.env.PORT || 8080;
var flash    = require('connect-flash');

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var TotpStrategy = require('passport-totp').Strategy;

var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var session      = require('express-session');

var MongoDBStore = require('connect-mongodb-session')(session); // Can swap for any other database store we want - https://github.com/expressjs/session#compatible-session-stores
var mongoose = require('mongoose');
var configDB = require('./config/database.js');

var RateLimit = require('express-rate-limit');

// configuration ===============================================================
mongoose.connect(configDB.userStore); // connect to our database for user storage

var store = new MongoDBStore({ // connect to our database for session storage
  uri: configDB.sessionStore,
  collection: 'mySessions'
});

require('./config/passport')(passport); // pass passport for configuration

// set up our express application
app.use(morgan('dev')); // log every request to the console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser.json()); // get information from html forms
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'ejs'); // set up ejs for templating

// required for passport
app.use(session({
    secret: 'TEC Test App', // session secret
    store: store,
    resave: true,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

var limiter = new RateLimit({ // Setup a rate limiter 
  windowMs: 15*60*1000, // 15 minutes 
  max: 250, // request limit per windowMs
  delayMs: 0 // disable delaying between requests
});
 
app.use(limiter); // apply to all requests 

// routes ======================================================================
require('./app/routes.js')(app, passport); // load our routes and pass in our app and fully configured passport

// launch ======================================================================
app.listen(port);
console.log('The magic happens on port ' + port);