const oauth2orize = require('oauth2orize');
const uid = require('uid2');
const { ObjectId } = require('mongodb');

class OAuth {
	constructor(db) {
		this.server = oauth2orize.createServer();

		this.server.serializeClient((client, callback) => {
			callback(null, client._id.toString());
		});
		this.server.deserializeClient(async (id, callback) => {
			try {
				const client = await db.find('oauth2.clients', { _id: new ObjectId(id) });
				callback(null, client);
			}
			catch (err) {
				callback(err);
			}
		});
		this.server.grant(oauth2orize.grant.code(async (client, redirectUri, user, ares, callback) => {
			try {
				const code = await db.create('oauth2.codes', {
					value: uid(16),
					redirectUri: redirectUri,
					clientId: client._id,
					userId: user._id
				});
				callback(null, code.value);
			}
			catch (err) {
				callback(err);
			}
		}));
		this.server.exchange(oauth2orize.exchange.code(async (client, code, redirectUri, callback) => {
			try {
				const authCode = await db.find('oauth2.codes', { value: code });
	
				if (authCode == null || !authCode.clientId.equals(new ObjectId(client)) || redirectUri !== authCode.redirectUri) {
					callback(null, false);
					return;
				}
	
				await db.remove('oauth2.codes', { value: code });
	
				let token = await db.find('oauth2.tokens', {
					clientId: authCode.clientId,
					userId: authCode.userId
				});
				if (token == null) {
					token = await db.create('oauth2.tokens', {
						accessToken: uid(256),
						clientId: authCode.clientId,
						userId: authCode.userId
					});
				}
				callback(null, token.accessToken, null);
			}
			catch (err) {
				callback(err);
			}
		}));
	}
}
module.exports = OAuth;
