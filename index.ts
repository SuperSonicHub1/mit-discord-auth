import express from "express"
import session, { Store } from "express-session"
import passport from "passport"
import DiscordStrategy from "passport-discord"
import OpenIDConnectStrategy, { Profile, VerifyCallback } from "passport-openidconnect"
import Database from 'better-sqlite3'
import SQLiteStoreFactory from 'connect-sqlite3'
import { Client, GatewayIntentBits } from 'discord.js'
import "dotenv/config"
import assert from "node:assert"

/* Developer options */
const DEVELOPING = true
const PORT = DEVELOPING ? 11861 : 80

/* Database */
const db = new Database(':memory:')
db.pragma('journal_mode = WAL')

// Tables
db.exec(/*sql*/`CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY,
	username TEXT
);

CREATE TABLE IF NOT EXISTS federated_credentials (
	user_id INTEGER,
	issuer TEXT,
	subject TEXT,
	profile JSON,
	FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);`)

type User = {
	id: number
	username: string
}

type Credentials = {
	user_id: number
	issuer: 'mit' | 'discord'
	subject: string
	profile: string
}

/* Passport */

passport.use(new OpenIDConnectStrategy(
	{
		issuer: 'https://oidc.mit.edu/',
		authorizationURL: 'https://oidc.mit.edu/authorize',
		tokenURL: 'https://oidc.mit.edu/token',
		callbackURL: new URL('/auth/mit/callback', `http://${DEVELOPING ? `localhost:${PORT}` : 'mit-2027-discord-auth.xvm.mit.edu'}`).toString(),
		userInfoURL: 'https://oidc.mit.edu/userinfo',
		clientID: process.env.MIT_CLIENT_ID as string,
		clientSecret: process.env.MIT_CLIENT_SECRET as string,
		scope: [ 'openid', 'profile', 'email' ],
		customHeaders: {
			Authorization: `Bearer ${process.env.MIT_REGISTRATION_ACCESS_TOKEN as string}`
		},
	},

	// https://github.com/jaredhanson/passport-openidconnect#configure-strategy
	function verify(issuer: string, profile: Profile, cb: VerifyCallback) {
		try {
			const creds = db
				.prepare(/*sql*/`SELECT * FROM federated_credentials WHERE issuer = ? AND subject = ?`)
				.get('mit', profile.id) as Credentials

			let user: User

			if (creds) {
				user = db
					.prepare(/*sql*/`SELECT * FROM federated_credentials WHERE issuer = ? AND subject = ?`)
					.get('mit', creds.user_id) as User
			} else {
				user = db
					.prepare(/*sql*/`INSERT INTO users (username) VALUES (?) RETURNING *`)
					.get(profile.username || (profile.emails && profile.emails[0].value)|| profile.displayName) as User

				db
					.prepare(/*sql*/`INSERT INTO federated_credentials (user_id, issuer, subject, profile) VALUES (?, ?, ?, ?)`)
					.run(user.id, 'mit', profile.id, JSON.stringify(profile))
			}

			return cb(null, user)
		} catch (error) {
			return cb(error)
		}
	}
))

passport.use(new DiscordStrategy(
	{
		clientID: process.env.DISCORD_CLIENT_ID as string,
		clientSecret: process.env.DISCORD_CLIENT_SECRET as string,
		callbackURL: `http://${DEVELOPING ? `localhost:${PORT}` : 'mit-2027-discord-auth.xvm.mit.edu'}/auth/discord/callback`,
		scope: ['identify'],
		passReqToCallback: true,
	},
	function verify(req, accessToken, refreshToken, profile, cb) {
		try {
			assert(req.user, 'You must login to your MIT account before logging in with Discord.')
			const user = req.user as User

			console.log(profile)

			const creds = db
				.prepare(/*sql*/`SELECT * FROM federated_credentials WHERE issuer = ? AND subject = ? AND user_id = ?`)
				.get('discord', profile.id, user.id) as Credentials


			if (!creds) {
				db
					.prepare(/*sql*/`INSERT INTO federated_credentials (user_id, issuer, subject, profile) VALUES (?, ?, ?, ?)`)
					.run(user.id, 'discord', profile.id, JSON.stringify(profile))
			}

			return cb(null, user)
		} catch (error) {
			return cb(error)
		}
	}
))

passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((user, done) => done(null, user as Express.User))

/* Server */
const SQLiteStore = SQLiteStoreFactory(session)

const app = express()
app.use(session({
	secret: process.env.MIT_CLIENT_SECRET as string,
	resave: false,
	saveUninitialized: false,
	store: new SQLiteStore({ concurrentDB: 'true' }) as Store,
}))
app.use(passport.authenticate('session'))

app.get('/', (req, res) => {
	const { session, user } = req
	res.json({ session, user, login: 'http://localhost:11861/login' })
})

app.get('/login', (req, res) => res.redirect('/auth/mit'))

app.get('/auth/mit', passport.authenticate('openidconnect'))
app.get(
	'/auth/mit/callback',
	passport.authenticate('openidconnect', {
		successReturnToOrRedirect: '/auth/discord',
		failureRedirect: '/', 
		failureMessage: true,
		keepSessionInfo: true,
	})
)

app.get('/auth/discord', passport.authenticate('discord'))
app.get(
	'/auth/discord/callback',
	passport.authenticate('discord', {
		successReturnToOrRedirect: '/',
		failureRedirect: '/', 
		failureMessage: true,
		keepSessionInfo: true,
	})
)

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`))
