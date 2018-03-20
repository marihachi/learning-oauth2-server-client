const { ObjectId } = require('mongodb');
const uid = require('uid2');
const debug = require('./debug');

const oauth2orize = require('oauth2orize');

const passport = require('passport');
const { BasicStrategy } = require('passport-http');
const { Strategy : ClientPasswordStrategy } = require('passport-oauth2-client-password');
const { Strategy : BearerStrategy } = require('passport-http-bearer');

class OAuthServer {
	constructor(db) {
		this._db = db;
	}

	build() {
		this._server = oauth2orize.createServer();

		this._server.serializeClient((client, callback) => {
			debug('クライアントをシリアライズ');
			callback(null, client._id.toString());
		});
		this._server.deserializeClient(async (id, callback) => {
			try {
				const client = await this._db.find('oauth2.clients', { _id: new ObjectId(id) });
				debug('クライアントをデシリアライズ');
				callback(null, client);
			}
			catch (err) {
				debug('クライアントのデシリアライズに失敗');
				callback(err);
			}
		});
		this._server.grant(oauth2orize.grant.code(async (client, redirectUri, user, ares, callback) => {
			try {
				const code = await this._db.create('oauth2.codes', {
					value: uid(16),
					redirectUri: redirectUri,
					clientId: client._id,
					userId: user._id
				});
				debug('コードの登録に成功');
				callback(null, code.value);
			}
			catch (err) {
				debug('コード取得時にエラーが発生');
				callback(err);
			}
		}));
		this._server.exchange(oauth2orize.exchange.code(async (client, code, redirectUri, callback) => {
			try {
				const authCode = await this._db.find('oauth2.codes', { value: code });

				if (authCode == null || !authCode.clientId.equals(client._id) || redirectUri !== authCode.redirectUri) {
					debug('コード、クライアント、リダイレクトURLのいずれかが不正');
					return callback(null, false);
				}

				await this._db.remove('oauth2.codes', { value: code });
				debug('コードを削除');

				let token = await this._db.find('oauth2.tokens', {
					clientId: authCode.clientId,
					userId: authCode.userId
				});
				if (token == null) {
					token = await this._db.create('oauth2.tokens', {
						accessToken: uid(256),
						clientId: authCode.clientId,
						userId: authCode.userId
					});
					debug('トークンの登録に成功');
				}
				debug('コードとトークンの交換に成功');
				callback(null, token.accessToken, null);
			}
			catch (err) {
				debug('コードとトークンの交換時にエラーが発生');
				callback(err);
			}
		}));
	}

	defineStrategies() {
		const verifyClient = async (clientId, secret, done) => {
			try {
				const client = await this._db.find('oauth2.clients', { _id: new ObjectId(clientId) });
				if (client == null || secret !== client.secret) {
					debug('クライアントの認証に失敗');
					return done(null, false);
				}
				debug('クライアントの認証に成功');
				done(null, client);
			}
			catch (err) {
				debug('クライアントの認証時にエラーが発生');
				done(err);
			}
		};
		passport.use('clientBasic', new BasicStrategy(verifyClient));
		passport.use('clientPassword', new ClientPasswordStrategy(verifyClient));

		passport.use('accessToken', new BearerStrategy(async (accessToken, done) => {
			try {
				const token = await this._db.find('oauth2.tokens', {
					accessToken: accessToken
				});
				if (token == null) {
					done(null, false);
					return;
				}
				const user = await this._db.find('users', { _id: token.userId });
				if (user == null) {
					done(null, false);
					return;
				}
				done(null, user);
			}
			catch (err) {
				done(err);
			}
		}));
	}
}
module.exports = OAuthServer;
