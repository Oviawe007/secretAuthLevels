//jshint esversion:6
require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
//const encrypt = require('mongoose-encryption');
//const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));
app.use(session({secret : "Our Little Secret!", resave : false , saveUninitialized : false}));
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser : true})
.then(() => console.log("Connected to Database successfully!"))
.catch(err => console.error(err));


const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId : String,
    secret : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)

//ENCRYPTION
//userSchema.plugin(encrypt, { secret: process.env.SECRET_KEY , encryptedFields: ['password']});

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});
//
//
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//TODO

app.get("/", function(req, res) {
    res.render("home");
});
//
app.get("/auth/google", 
    passport.authenticate('google', { scope: ['profile'] })
);
//
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secret.
    res.redirect('/secrets');
});
//

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.get("/secrets", function(req, res) {
   
    User.find({"secret": {$ne: null}}, function(err, foundSecrets){
        if (!err){
            res.render("secrets", {secrets : foundSecrets});
        }
       
    });
      
       
    
});

app.post("/register", function(req, res) {

    const email  = req.body.username;
    const password = req.body.password;

    User.register({username : req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.error(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets"); 
            });
        }
    });

    // bcrypt.hash(password,saltRounds, function(err, hash) {
    //     // Store hash in your password DB.
    //     if (!err) {
    //         const newUser = new User({
    //             email : email,
    //             password : hash
    //         });
        
    //         newUser.save()
    //         .then(() => res.render('secrets'))
    //         .catch(err => console.error(err));
    //     }

    // })      
    
});

app.post('/login', function(req, res) {
    const email = req.body.username;
    const password = req.body.password;

    const user = new User({username: email, password: password});

    req.login(user , function(err) {
        if (err) {
            console.error(err);
        } else{
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets"); 
            });
        }
    });

    //const password = md5(req.body.password);
    // User.findOne({ email: email }, function(err, foundUser) {
    //     if (err) {
    //         console.error(err);
    //     } else {
    //         if (foundUser) {
    //             bcrypt.compare(password, foundUser.password, function(err, result) {
    //                 // result == true
    //                 if (err){
    //                     console.log(err);
    //                 } else {
    //                     if (result === true) {
    //                         res.render('secrets');
    //                 }}
    //             });
                
    //         } else {
    //             //res.send()
    //         };
    //     }
    // });
});

app.get("/logout", function(req, res){
    req.logout(function(err){
        if(!err){
            res.redirect('/');
        }
    });
});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){

    const secretSubmitted = req.body.secret;

    //console.log(req.user);
    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.error(err);
        } else {
            if (foundUser) {
                foundUser.secret = secretSubmitted;
                foundUser.save(function(err){
                    if (!err) {
                        res.redirect("/secrets");
                    }
                });
            }
            
        }
    });

});






app.listen(3000, function() {
  console.log("Server started on port 3000");
});
