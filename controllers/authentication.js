const User = require("../models/user.js");
const jwt = require("jwt-simple");
const config = require("../config.js");

function tokenForUser(user) {
	const timestamp = new Date().getTime();
	return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signup = function(req, res, next) {
	const email = req.body.email;
	const password = req.body.password;

	if (email == undefined || email == "") {
		return res.status(422).send({ error: "Email cannot be blank" });
	}

	if (password == undefined || password == "") {
		return res.status(422).send({ error: "Password cannot be blank" });
	}

	User.findOne({ email: email }, function(err, existingUser) {
		if (err) {
			return next(err);
		}
		//If email is already in use return error notification.
		if (existingUser) {
			return res.status(422).send({ error: "Email is already in use." });
		}

		//If this is a new email create and save record.
		const user = new User({ email: email, password: password });
		user.save(function(err) {
			if (err) {
				return next(err);
			}
			res.json({ token: tokenForUser(user) });
		});
	});
};

exports.signin = function(req, res, next) {
	res.send({ token: tokenForUser(req.user) });
};
