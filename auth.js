// Load required packages
var passport = require('passport');
var BasicStrategy = require('passport-http').BasicStrategy;

passport.use(new BasicStrategy(
    function(username, password, done) {
        var user = db.findOne(username);
        if (user != null && username == user.username && password == user.password)
        {
            return done(null, { name: user.username });
        }
        else
        {
            return done(null, false);
        }
    }
));

exports.isAuthenticated = passport.authenticate('basic', { session : false });