
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 24 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    var state = req.query.state;
    
    var html = `
        <h1>Welcome to my website!</h1>
        <h3>There are plenty of interesting things to do here</h3>
        <br>
    `;
    
    if (!req.session.authenticated) {
        html += `
        <form action='/login' method='get'>
            <button style='font-size: 32px'>Login</button>
        </form>
        <form action='/signup' method='get'>
            <button style='font-size: 32px'>Sign up</button>
        </form>
        `;

        if (state == 0) {
            html += `<h1 style='color: red'>The members section is for <i>members</i> only!</h1>`;
        }
    } else {
        html += `
        <form action='/members' method='get'>
            <button style='font-size: 32px'>Members</button>
        </form>
        <form action='/logout' method='get'>
            <button style='font-size: 32px'>Logout</button>
        </form>
        `;
    }
    res.send(html);
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/?state=0');
    }
    var html = `
    <h1>Welcome to the members only page ${req.session.username}!</h1>
    <h2>Here's a random WW2 tank</h2>
    `;

    var ran = Math.floor(Math.random() * 3);

    if (ran == 0) {
        html += "SHERMAN: <img src='/sherman.jpg'>";
    }
    else if (ran == 1) {
        html += "TIGER: <img src='/tiger.jpg'>";
    }
    else if (ran == 2) {
        html += "KV-2: <img src='/kv2.jpg'>";
    }
    res.send(html);
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    var html = `
    <h1>You have been logged out!</h1>
    `;
    res.send(html);
});

app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;

    var state = req.query.state;

    if (state == 0) {
        html = html + `<h1 style='color: red'>Credentials are not valid</h1>`;
    }

    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;

    var state = req.query.state;

    if (state == 0) {
        html = html + `<h1 style='color: red'>Incorrect username</h1>`;
    }

    if (state == 1) {
        html = html + `<h1 style='color: red'>Incorrect password</h1>`;
    }

    if (state == 2) {
        html = html + `<h1 style='color: red'>Credentials are not valid</h1>`;
    }

    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, password});
	if (validationResult.error != null) {
	   res.redirect("/signup?state=0");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, password: hashedPassword});

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   res.redirect("/login?state=2");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		res.redirect("/login?state=0");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		res.redirect("/login?state=1");
		return;
	}
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 