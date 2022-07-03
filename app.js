const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

const mongoose = require("mongoose");
const Schema = mongoose.Schema;
mongoose.connect('mongodb+srv://wkdvie:020290Ab@cluster0.f1b0g.mongodb.net/?retryWrites=true&w=majority', { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// get acces to the 'currentUser' variable (this function have to live between paspport instantiate an the rendered views)
app.use(function(req, res, next) {
    res.locals.currentUser = req.user; // set local variable 
    next();
  });

// render index on /
app.get("/", (req, res) => {
  res.render("index", { user: req.user }); // passport pass user
});

// render sign-up-form on /sign-up route
app.get("/sign-up", (req, res) => {
    res.render("sign-up-form");
});

// post for the sig-up to add users to database
app.post("/sign-up", (req, res, next) => {
    // create new user, get the username and password hash the password
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if(err){
            console.log('hashing password error');
        } else {
        // otherwise, store hashedPassword in DB
            const user = new User({
                username: req.body.username,
                password: hashedPassword
            }).save(err => {
                // error handing
                if(err) {
                    return next(err);
                };
                // redirect after
                res.redirect("/");
            });
        };
      });

});

// try to find 'User' in the db with POSTing username and password (hashed)
passport.use(
    new LocalStrategy((username, password, done) => {
      User.findOne({ username: username }, (err, user) => {
        if (err) { 
          return done(err);
        };
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        };
        bcrypt.compare(password, user.password, (err, res) => {
            if (res) {
                // passwords match! log user in
                return done(null, user)
            } else {
                // passwords do not match!
                return done(null, false, { message: "Incorrect password" })
            }
        });
      });
    })
);

  // background functions for passport (logged in authentication)
passport.serializeUser(function(user, done) {
    done(null, user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
});

  // get the POSTing from the html form and try to authenticate and redirect. This function runs numerous background functions, f.e. looks at the request body for parameters named username and password then runs the LocalStrategy function to find it in DB, than creat a session cookie and...
app.post(
    "/log-in",
    passport.authenticate("local", {
      successRedirect: "/", // maybe redirect to user dashboard
      failureRedirect: "/"   // maybe redirect to login form again
    })
);

// logout and redirect to /
app.get("/log-out", (req, res) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });

app.listen(3000, () => console.log("app listening on port 3000!"));