//jshint esversion:6
.s
const mongoose = require('mongoose');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const app = express();
const cookieParser = require("cookie-parser");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const Promise = require('es6-promise').Promise;
const findOrCreate = require('mongoose-findorcreate');

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Algo deu errado!');
})

mongoose.connect(process.env.DBURL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Conexão com o MongoDB estabelecida com sucesso!'))
    .catch(error => console.log('Erro ao conectar com o MongoDB: ' + error));

const secretSchema = new mongoose.Schema({
    secret: String
})

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose, { noPromise: true });
userSchema.plugin(findOrCreate);

const Secret = new mongoose.model('Secret', secretSchema);
const User = new mongoose.model('User', userSchema);


passport.use(User.createStrategy());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then((user) => {
            done(null, user);
        })
        .catch((err) => done(err));
})


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:3080/auth/google/secrets',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
},
    function (accessToken, refreshToken, profile, done) {

        if (!profile) {
            return cb(null, null);
        }

        console.log(profile);

        User.findOne({ googleId: profile.id })
            .then((err, user) => {
                if (err) {
                    return done(err)
                }

                if (!user) {
                    user = new User({
                        googleId: profile.id
                    });
                    user.save()
                        .then((err) => {
                            if (err) console.log(err);
                            return cb(err, user);
                        })
                } else {
                    console.log('estou aqui');
                    return done(err, user);
                }
            }).catch((err) => console.log(err));

    }
));

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        console.log("Autenticação com Google bem sucedida");
        // Successful authentication, redirect to secrets.
        res.redirect('/secrets');
    });

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/secrets', (req, res) => {
    console.log('cheguei - secrets');
    if (req.isAuthenticated()) {
        console.log('cheguei aqui - secrets');
        User.find({ 'secret': { $ne: null } })
            .then((foundUsers) => {
                if (foundUsers) {
                    res.render('secrets', { usersWithSecrets: foundUsers })
                }
            }).catch((err) => { console.log(err); })
    } else {
        res.redirect('/login');
    }
});

app.post('/register', (req, res) => {

    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        console.log("cheguei aqui");
        if (err) {
            console.log(err);
            res.redirect("/register");
            console.log("cheguei aqui 2");
        } else {
            if (user) {
                passport.authenticate('local')(req, res, () => {
                    console.log('cheguei aqui 3');
                    res.redirect('/secrets');

                })
            }
        }
    })

});

app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate('local', { failureRedirect: '/login' })(req, res, () => {
                res.redirect('/secrets');
            })
        }
    })
});

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        console.log('cheguei aqui - secrets');
        res.render('submit');
    } else {
        res.redirect('/login');
    }
});

app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;

    User.findById(req.user.id)
        .then((user) => {
            if (user) {
                user.secret = submittedSecret;
                user.save();
                res.redirect('/secrets');
            }
        }).catch((err) => console.log(err));
})

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }

        res.redirect('/')
    })
});


app.listen(3080, () => {
    console.log('O servidor está rodando na porta 3080');
})