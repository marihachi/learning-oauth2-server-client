process.on('unhandledRejection', err => console.log(err));

const debug = (...args) => {
	console.log('[client]', ...args);
};

const ClientOAuth2 = require('client-oauth2');
const auth = new ClientOAuth2({
	clientId: '5ab0fc3a5839b22fdccfe2c8',
	clientSecret: '123',
	accessTokenUri: 'http://localhost:3000/oauth/token',
	authorizationUri: 'http://localhost:3000/oauth/authorize',
	redirectUri: 'http://localhost:3001/auth/learning/callback',
	scopes: ['hoge']
});

var express = require('express');

const app = express();

app.get('/auth/learning', (req, res) => {
	const uri = auth.code.getUri();
	debug('認可URLを生成、リダイレクト:', uri);
	res.redirect(uri);
});

app.get('/auth/learning/callback', async (req, res) => {
	debug('コードとトークンの交換を要求');
	const token = await auth.code.getToken(req.originalUrl);
	debug('トークンの取得に成功:', token.accessToken);
	res.redirect('/');
});

app.listen(3001, () => {
	debug('started client on 3001 port');
});
