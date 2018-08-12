const passport = require("passport");
const User = require("../models/user.js");
const config = require("../config.js");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local");

//Creatre local strategy
const localOptions = { usernameField: "email" };
const localLogin = new LocalStrategy(localOptions, function(
	email,
	password,
	done
) {
	//Verify email and password.
	User.findOne({ email: email }, function(err, user) {
		if (err) {
			return done(err);
		}

		if (!user) {
			return done(null, false);
		}

		//Compare request password == user.password
		user.comparePassword(password, function(err, isMatch) {
			if (err) {
				return done(err);
			}

			if (!isMatch) {
				return done(null, false);
			}

			return done(null, user);
		});
	});
});

const jwtOptions = {
	jwtFromRequest: ExtractJwt.fromHeader("authorization"),
	secretOrKey: config.secret
};

const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
	//Check database for the existence of the user id.
	User.findById(payload.sub, function(err, user) {
		if (err) {
			return done(err, false);
		}

		if (user) {
			done(null, user); //User exist
		} else {
			done(null, false); //user doesn't exist
		}
	});
});

passport.use(jwtLogin);
passport.use(localLogin);
