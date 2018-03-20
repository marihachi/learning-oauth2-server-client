const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const { ObjectId } = require('mongodb');
const passport = require('passport');
const { Strategy : LocalStrategy } = require('passport-local');
const MongoAdapter = require('./modules/MongoAdapter');
const OAuthServer = require('./modules/OAuthServer');
const session = require('express-session');
const connectRedis = require('connect-redis');
const debug = require('./modules/debug');

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

	// passport

	// 通常のログイン認証向け
	passport.use('login', new LocalStrategy(async (screenName, password, done) => {
		try {
			const user = await db.find('users', { screenName: screenName });
			if (user == null || user.password != password) {
				return done(null, false);
			}
			done(null, user);
		}
		catch (err) {
			done(err);
		}
	}));
	// セッションとユーザー情報を関連付けるために必要
	passport.serializeUser((user, done) => {
		done(null, user._id);
	});
	passport.deserializeUser(async (id, done) => {
		try {
			const user = await db.find('users', { _id: new ObjectId(id) });
			done(null, user);
		}
		catch (err) {
			done(err);
		}
	});

	// 仮データを登録

	// クライアントデータ
	let client = await db.find('oauth2.clients', { name: 'hoge' });
	if (client == null) {
		client = await db.create('oauth2.clients', {
			name: 'hoge',
			secret: '123'
		});
	}
	console.log(`clinetId: ${client._id.toString()}`);
	// ユーザーデータ
	let user = await db.find('users', { screenName: 'piyo' });
	if (user == null) {
		user = await db.create('users', {
			screenName: 'piyo',
			password: 'hoge'
		});
	}

	const oAuthServer = new OAuthServer(db);
	oAuthServer.build();
	oAuthServer.defineStrategies();

	app.get('/', (req, res) => {
		res.render('top', { user: req.user });
	});

	app.get('/account', (req, res) => {
		if (!req.isAuthenticated())
			return res.status(403).send('need login');

		res.render('account', { user: req.user });
	});

	app.get('/login', (req, res) => {
		res.render('login', { });
	});
	app.post('/login', passport.authenticate('login', { successRedirect: '/', failureRedirect: '/login' }));
	app.post('/logout', (req, res) => {
		req.logout();
		res.redirect('/');
	});

	app.route('/oauth/authorize')
		.get(oAuthServer._server.authorization(async (clientId, redirectUri, validated) => {
			try {
				const client = await db.find('oauth2.clients', { _id: new ObjectId(clientId) });
				// TODO: 検証処理
				debug('認可の検証に成功');
				validated(null, client, redirectUri);
			}
			catch (err) {
				debug('認可の検証でエラーが発生');
				validated(err);
			}
		}, async (client, user, immediated) => {
			try {
				const token = await db.find('oauth2.tokens', { clientId: client._id, userId: user._id });
				if (token != null) {
					debug('即時に認可');
					return immediated(null, true);
				}
				debug('認可フォームを表示');
				immediated(null, false);
			}
			catch (err) {
				debug('即時判定でエラーが発生');
				immediated(err);
			}
		}), (req, res) => {
			res.render('authorizationDialog', { tid: req.oauth2.transactionID, user: req.user, client: req.oauth2.client });
		})
		.post(oAuthServer._server.decision());

	app.post('/oauth/token',
		passport.authenticate(['clientBasic', 'clientPassword'], { session: false }),
		oAuthServer._server.token());

	app.get('/api', passport.authenticate('accessToken', { session: false }), (req, res) => {
		res.send('api area');
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
