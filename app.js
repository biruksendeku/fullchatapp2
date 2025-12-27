const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cron = require('node-cron');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
// const util = require('util');
const crypto = require('crypto');
const path = require('path');
const { createServer } = require('http');
require('dotenv').config();

const { User, Brt } = require('./models/userStuff');

const app = express();
const port = process.env.PORT || 3000;
const publicFolder = path.join(__dirname, 'public');

const server = createServer(app);

const io = require('socket.io')(server);

// app settings
app.set('view engine', 'ejs');
app.set('view cache', false);

// built-in middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicFolder));
app.use(cookieParser());
app.use(cors({
	origin: 'http://localhost:8000'
}));
app.use(
	helmet.contentSecurityPolicy(({
		directives: {
			defaultSrc: ["'self'"], //allow from the same origin only
			scriptSrc: ["'self'"], // allow script from same origin only
			styleSrc: ["'self'"], // sttles too
			imgSrc: ["'self'"]
		},
	}))
);
app.use(
	helmet({
		xPoweredBy: false,
		frameguard: true, // this is true by default though
	})
);

// cron stuff
cron.schedule('0 0 * * *', async () => {
	const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
	await User.deleteMany({
		isVerified: false,
		createdAt: { $lt: sevenDaysAgo }
	});
	
	console.log("Cleared Emails that weren't verified for 7 days.");
});

// custom middlewares
// nodemailer stuff
const transporter = nodemailer.createTransport({
	service: 'Gmail',
	auth: {
		user: process.env.EMAIL_USER,
		pass: process.env.EMAIL_PASS
	}
});

const sendVerificationEmail = async (email, token) => {
	const verificationUrl = `${process.env.BASE_URL}/api/verify-email/${token}`;
	const mailOptions = {
		from: process.env.EMAIL_USER,
		to: email,
		subject: 'Verify Your Email',
		html: `
		<h1> Verify Your Email </h1>
		<p> Click on the link below to verify your account: </p>
		<a href="${verificationUrl}"> Verify Here </a>
		<p> This link will expire in 24 hours. </p>
		`
	};
	await transporter.sendMail(mailOptions);
};

// jwt based auth stuff
const verifyAccessToken = async (req, res, next) => {
	try {
		const accessToken = req.cookies.accessToken;
		const refreshToken = req.cookies.refreshToken;
		if(!refreshToken) {
			return res.redirect('/login'); // to stop access as soon as the log-out
		}
		if(!accessToken) {
			return await verifyRefreshToken(req, res, next);
		}
		// there's access token
		try {
			const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_KEY);
			// pass the data to the req obj
			req.user = decoded;
			next();
		} catch(err) {
			await verifyRefreshToken(req, res, next);
		}

	} catch(err) {
		next(err);
	}
};

const verifyRefreshToken = async (req, res, next) => {
	try {
		const refreshToken = req.cookies.refreshToken;
		if(!refreshToken) {
			return res.redirect('/login'); // show no mercy😂
		}
		// there's refresh token
		const brt = await Brt.findOne({ brt: refreshToken });
		if(brt) {
			res.clearCookie('refreshToken',);
			res.clearCookie('accessToken');
			return res.redirect('/login');
		}
		try {
			const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY);
			// pass the data to use to generate another aaccess token

			/*if(!decoded.id) { //🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕🆕
				const url = req.originalUrl;
				return res.redirect(`/${url}`);
			}*/
			req.user = decoded;
			const newAccessToken = jwt.sign({ id: req.user.id }, process.env.ACCESS_TOKEN_KEY, { expiresIn: '2m' });

			res.cookie('accessToken', newAccessToken, {
				httpOnly: true,
				secure: process.env.NODE_ENV !== 'development',
				sameSite: 'strict',
				maxAge: 2 * 60 * 1000 //2 mins
			});
			// verifyAccessToken(req, res, next); // wow logic, it's better approach than calling next
			const decodedAT = jwt.verify(newAccessToken, process.env.ACCESS_TOKEN_KEY);
			req.user = decodedAT;
			return next();
		} catch(err) {
			res.redirect('/login');
		}

	} catch(err) {
		next(err);
	}
};

// rate limiter stuff
const loginLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: 10, // I guess it's more than enough for normal user
	message: 'Too many requests. Try again later.'
});
app.use('/signup', loginLimiter);
app.use('/login', loginLimiter);

const apiLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 mins
	max: 20, // since these are more than 1 endpoint
	message: 'Too many request. Try again later.'
});
app.use('/api', apiLimiter);

const normalLimiter = rateLimit({
	windowMs: 2 * 60 * 1000, // 2 minutes
	max: 20, // 1 req per 6 secs is nice
	message: 'Too many requests. Try again later.'
});

// CRUD operation
app.get('/signup', (req, res, next) => {
	try {
		res.render('signup');
	} catch(err) {
		next(err);
	}
});

app.post('/signup',[
	body('name')
	.trim()
	.escape()
	.notEmpty()
	.withMessage('Invalid Credentials - Name field required'),
	body('email')
	.trim()
	.escape()
	.notEmpty()
	.withMessage('Invalid Credentials - Email field required')
	.isEmail()
	.normalizeEmail()
	.withMessage('Invalid Credentials - Invalid Email address'),
	body('password')
	.notEmpty()
	.withMessage('Invalid Credentials - Password field required')
	.isLength({ min: 6 })
	.withMessage('Invalid Credentials - Minimum Password length should be 6 characters long'),
	body('confirmPassword')
	.notEmpty()
	.withMessage('Invalid Credentials - Confirm Password field required')
], async (req, res, next) => {
	try {
		const errors = validationResult(req);
		if(!errors.isEmpty()) {
			return next(new Error(JSON.stringify(errors.array()) ))
		}

		const { name, email, password, confirmPassword } = req.body;
		if(!name || !email || !password || !confirmPassword) {
			return next(new Error('Invalid Credentials - Missing Credentials'));
		}
		if(password !== confirmPassword) {
			return next(new Error('Invalid Credentials - Password Mismatch'));
		}
		const user = await User.findOne({ email });
		if(user) {
			return next(new Error('Email already registered. Login to continue.'));
		}
		// new email
		const hashedPassword = await bcrypt.hash(password, 10);
		const name2 = name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
		const verificationToken = crypto.randomBytes(32).toString('hex');
		const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 1day plus

		const newUser = new User({
			name: name2,
			email,
			password: hashedPassword,
			verificationToken,
			verificationExpires
		});

		await newUser.save();
		await sendVerificationEmail(email, verificationToken);
		// let the user know
		res.status(200).send(`
			<h1> Registration Successful. </h1>
			<h2> Please check your email to verify your account. </h2>
		`);
		
	} catch(err) {
		next(err);
	}
});

app.get('/login', (req, res, next) => {
	try {
		res.render('login');
	} catch(err) {
		next(err);
	}
});

app.get('/api/verify-email/:token', async (req, res, next) => {
	try {
		const token = req.params.token.toString();
		const user = await User.findOne({
			verificationToken: token,
			verificationExpires: { $gt: Date.now() }
		});
		if(!user) {
			// msg with resend form page
			return res.redirect('/api/resend-verification-link');
		}
		// there's a user
		user.verificationToken = undefined; // delete the key too
		user.verificationExpires = undefined;
		user.isVerified = true; // the key part
		user.verifiedAt = Date.now(); // extra info
		// save these updates
		await user.save();
		// give rt and at and redirect to profile - phew
		// console.log('user: ', user);
		// console.log('user.id: ', user.id);
		const refreshToken = jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_KEY, { expiresIn: '5m' });
		const accessToken = jwt.sign({ id: user._id }, process.env.ACCESS_TOKEN_KEY, { expiresIn: '2m' });

		res.cookie('refreshToken', refreshToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV !== 'development',
			sameSite: 'strict',
			maxAge: 5 * 60 * 1000 // 5 minutes
		});
		res.cookie('accessToken', accessToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV !== 'development',
			sameSite: 'strict',
			maxAge: 2 * 60 * 1000 // 2 minutes
		});
		// we can safely redirect to profile, without any need to login!!!
		res.redirect('/profile');
		
	} catch(err) {
		next(err);
	}
});

app.get('/api/resend-verification-link', (req, res, next) => {
	try {
		res.render('resend');
	} catch(err) {
		next(err);
	}
});

app.post('/api/resend-verification-link', [
	body('email')
	.trim()
	.escape()
	.notEmpty()
	.withMessage('Invalid Credentials - Email field required')
	.isEmail()
	.normalizeEmail()
	.withMessage('Invavlid Credentials - Invalid Email address')
], async (req, res, next) => {
	try {
		const errors = validationResult(req);
		if(!errors.isEmpty()) {
			return next(new Error(JSON.stringify(errors.array()) ));
		}
		
		const { email } = req.body;
		if(!email) {
			return next(new Error('Invalid Credentials - Email field required'));
		}
		// user lookup
		const user = await User.findOne({ email });
		if(!user) {
			return next(new Error('Bad Request - Invalid Credentials'));
		}
		// there's user
		if(user.isVerified === true) {
			return next(new Error('Bad Request - Email already verified'));
		}
		// there's unverified user
		const verificationToken = crypto.randomBytes(32).toString('hex');
		const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 1day plus
		
		user.verificationToken = verificationToken;
		user.verificationExpires = verificationExpires;
		// save these patches
		await user.save();
		// send email
		await sendVerificationEmail(email, verificationToken);
		// let the user know
		res.status(200).send('Verification Link Resent. Please check your email to verify your account.');
		
	} catch(err) {
		next(err);
	}
});

app.post('/login', [
	body('email')
	.trim()
	.escape()
	.notEmpty()
	.withMessage('Invalid Credentials - Email field required')
	.isEmail()
	.normalizeEmail()
	.withMessage('Invalid Credentials - Invalid Email address'),
	body('password')
	.notEmpty()
	.withMessage('Invalid Credentials - Password field required')
], async (req, res, next) => {
	try {
		const errors = validationResult(req);
		if(!errors.isEmpty()) {
			return next(new Error(JSON.stringify(errors.array()) ));
		}
		const { email, password } = req.body;
		if(!email || !password) {
			return next(new Error('Invalid Credentials - Missing Credentials'));
		}
		const user = await User.findOne({ email });
		if(!user) {
			return next(new Error('Invalid Credentials - Incorrect Email or Password'));
		}
		// there's user
		const isValid = await bcrypt.compare(password, user.password);
		if(!isValid) {
			return next(new Error('Invalid Credentials - Incorrect Email or Password'));
		}
		// has true credentials offer rt and at
		const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_KEY, { expiresIn: '5m' });
		const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_KEY, { expiresIn: '2m' });

		// put on cookies
		res.cookie('refreshToken', refreshToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV !== 'development',
			sameSite: 'strict',
			maxAge: 5 * 60 * 1000, // 5 minutes
		});
		res.cookie('accessToken', accessToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV !== 'development',
			sameSite: 'strict',
			maxAge: 2 * 60 * 1000, // 2 minutes
		});

		res.redirect('/profile');
		
	} catch(err) {
		next(err);
	}
});

app.get('/profile', normalLimiter, verifyAccessToken, async (req, res, next) => {
	try {
		const user = await User.findById(req.user.id);
		if(!user) {
			return next(new Error('Bad Request'));
		}
		res.render('profile', {
			user: user
		});
	} catch(err) {
		next(err);
	}
});

app.get('/chat', normalLimiter, verifyAccessToken, async (req, res, next) => {
	try {
		const user = await User.findById(req.user.id);
		if(!user) {
			return next(new Error('Bad Request'));
		}
		io.on('connection', (socket) => {
			socket.on('user-connection', () => {
				socket.broadcast.emit('handle-user-connection', user.name);
			});
			socket.on('send-message', (data) => {
				data.name = user.name;
				socket.broadcast.emit('handle-send-message', data);
			});
			socket.on('user-disconnection', () => {
				socket.broadcast.emit('handle-user-disconnection', user.name);
			});
		});
		res.render('chat');
		
	} catch(err) {
		next(err);
	}
});

app.get('/logout', verifyAccessToken, async (req, res, next) => {
	try {
		const refreshToken = req.cookies.refreshToken;
		const newBrt = new Brt({
			brt: refreshToken
		});
		await newBrt.save();
		
		res.clearCookie('accessToken');
		res.clearCookie('refreshToken');
		res.redirect('/login');
		
	} catch(err) {
		next(err);
	}
});

app.use((req, res, next) => {
	try {
		next(new Error('404 - Page Not Found'));
	} catch(err) {
		next(err);
	}
});

app.use((err, req, res, next) => {
	if(process.env.NODE_ENV !== 'development') {
		console.log('Error Message: ', err.message);
		console.log('Error Stack: ', err.stack);
		return res.status(500).send('Internal Server Error');
	}
	res.json({ error: err.message });
});

server.listen(port, () => {
	console.log(`Server listening on port ${port}...`);
});
