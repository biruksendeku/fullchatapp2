const mongoose = require('mongoose');
const { isEmail } = require('validator');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
	console.log('Database Connected');
})
.catch((err) => {
	console.log('Failed to connect to DB: ', err.message);
	process.exit(1);
});

const userSchema = new mongoose.Schema({
	name: {
		type: String,
		required: [ true, 'Invalid Credentials - Name field required' ]
	},
	email: {
		type: String,
		unique: true,
		index: true, // for faster lookup
		required: [ true, 'Invalid Credentials - Email field required' ],
		validate: [ isEmail, 'Invalid Credentials - Invalid Email address' ]
	},
	password: {
		type: String,
		required: [ true, 'Invalud Credentials - Password field required' ],
		minlength: [ 6, 'Invalid Credentials - Minimum Password length should be 6 characters long' ]
	},
	isVerified: {
		type: Boolean,
		default: false
	},
	verifiedAt: {
		type: Date,
		default: null
	},
	verificationToken: String,
	verificationExpires: Date,
	createdAt: {
		type: Date,
		default: Date.now()
	}
});

// brt == blacklisted refresh token
const brtSchema = new mongoose.Schema({
	brt: {
		type: String,
		index: true, // since we use this for db lookup
	},
	createdAt: {
		type: Date,
		default: Date.now(),
		expires: 600, // 10 minutes, we can use longer
	}
});

const User = mongoose.model('user', userSchema);
const Brt = mongoose.model('brt', brtSchema);

module.exports = {
	User,
	Brt
};
