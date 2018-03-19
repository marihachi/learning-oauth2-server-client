process.on('unhandledRejection', err => console.log(err));

const ClientOAuth2 = require('client-oauth2');
const auth = new ClientOAuth2({
	clientId: '5aaea8eb947f8f04ec390f1b',
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
	res.redirect(uri);
});

app.get('/auth/learning/callback', async (req, res) => {
	const token = await auth.code.getToken(req.originalUrl);
	console.log('accessToken:', token.accessToken);
	res.redirect('/');
});

app.listen(3001, () => {
	console.log('started client on 3001 port');
});
