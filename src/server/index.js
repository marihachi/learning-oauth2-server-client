const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const { ObjectId } = require('mongodb');
const passport = require('passport');
const MongoAdapter = require('./modules/MongoAdapter');
const OAuth = require('./modules/OAuth');
const session = require('express-session');
const connectRedis = require('connect-redis');
const basicAuth = require('basic-auth-connect');

const sessionStore = new (connectRedis(session))({});

(async () => {
	process.on('unhandledRejection', err => console.log(err));

	const db = await MongoAdapter.connect('localhost:27017', 'test-oauth', 'test-oauth');

	const app = express();
	app.set('views', path.join(__dirname, 'views'));
	app.set('view engine', 'pug');
	app.use(bodyParser.urlencoded({ extended: true }));
	app.use(session({
		store: sessionStore,
		secret: 'secret_hoge',
		cookie: {
			//httpOnly: false,
			maxAge: 7 * 24 * 60 * 60 * 1000 // 7days
		},
		resave: false,
		saveUninitialized: true,
		rolling: true
	}));
	app.use(passport.initialize());
	app.use(passport.session());
	app.use(async (req, res, next) => {
		try {
			if (req.session.userId != null) {
				req.user = await db.find('users', { _id: new ObjectId(req.session.userId) });
				if (req.user == null) {
					req.session.userId = null;
				}
			}
			next();
		}
		catch (err) {
			next(err);
		}
	});

	// 仮のクライアントデータ
	let client = await db.find('oauth2.clients', { name: 'hoge' });
	if (client == null) {
		client = await db.create('oauth2.clients', {
			name: 'hoge',
			secret: '123'
		});
	}
	console.log(`clinetId: ${client._id.toString()}`);

	// 仮のユーザーデータ
	let user = await db.find('users', { name: 'piyo' });
	if (user == null) {
		user = await db.create('users', {
			name: 'piyo'
		});
	}

	const oauth = new OAuth(db).server;

	app.get('/', (req, res) => {
		res.send(req.user != null ? 'ログインしています' : 'ログインしていません');
	});

	app.put('/session', (req, res) => {
		req.session.userId = user._id.toString();
		res.send();
	});

	app.delete('/session', (req, res) => {
		req.session.userId = null;
		res.send();
	});

	app.route('/oauth/authorize')
		.get(oauth.authorization(async (clientId, redirectUri, validated) => {
			try {
				const client = await db.find('oauth2.clients', { _id: new ObjectId(clientId) });
				return validated(null, client, redirectUri);
			}
			catch (err) {
				return validated(err);
			}
		}, async (client, user, immediated) => {
			try {
				const token = await db.find('oauth2.tokens', { clientId: client._id, userId: user._id });
				if (token != null) {
					immediated(null, true);
					return;
				}
				immediated(null, false);
			}
			catch (err) {
				return immediated(err);
			}
		}),
		(req, res) => {
			res.render('authorizationDialog', { tid: req.oauth2.transactionID, user: req.user, client: req.oauth2.client });
		})
		.post(oauth.decision());

	app.post('/oauth/token', basicAuth('5aaea8eb947f8f04ec390f1b', '123'), oauth.token());

	app.get('/secure', passport.authenticate('bearer', { session: false }), (req, res) => {
		res.send('secure area');
	});

	app.use((err, req, res, next) => {
		if (err.status != null) {
			res.status(err.status);
		}
		res.json(err);
		console.log(err);
	});

	app.listen(3000, () => {
		console.log('start listening on 3000 port');
	});
})();
