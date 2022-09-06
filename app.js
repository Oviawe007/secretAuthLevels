//jshint esversion:6

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser : true})
.then(() => {console.log("Connected to Database successfully!");})
.catch(err => console.error(err));

const userSchema = {
    email : String,
    password : String
};

const User = new mongoose.model('User', userSchema);





//TODO

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.post("/register", function(req, res) {
    
    const newUser = new User({
        email : req.body.username,
        password : req.body.password
    });

    newUser.save()
    .then(() => res.render('secrets'))
    .catch(err => console.error(err));
});

app.post('/login', function(req, res) {
    const email = req.body.username;
    const password = req.body.password;

    User.findOne({ email: email }, function(err, foundUser) {
        if (err) {
            console.error(err);
        } else {
            if (foundUser) {
                if (foundUser.password === password) {
                    res.render('secrets');
                };
            } else {
                res.redirect('/register');
            };
        }
    });
});







app.listen(3000, function() {
  console.log("Server started on port 3000");
});