//jshint esversion:6
require('dotenv').config()
const encrypt = require('mongoose-encryption');
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const passportLocalMongoose = require('passport-local-mongoose');
//////////////////// MD5 Hashing ///////////////////////////
const md5 = require('md5');

/////////////////// Bcrypt - Hashing and salting /////////////////////
const bcrypt = require('bcrypt');
const saltRounds = 10;
const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SOME_LONG_UNGUESSABLE_STRING,
  resave: false,
  saveUninitialized: true,
}))

app.use(passport.initialize());
app.use(passport.session());
/////////////////////////////////////////// Schema Mongo //////////////////////////////////
mongoose.connect('mongodb://localhost:27017/users', {useNewUrlParser: true, useUnifiedTopology: true});

const { Schema } = mongoose;

const userschema = new Schema({
  username : String,
  password : String
});

/////////////////////////////////////////// Encryption ///////////////////////////////////

const secret = process.env.SOME_LONG_UNGUESSABLE_STRING;
//userschema.plugin(encrypt, { secret: secret , encryptedFields: ['password'] });

userschema.plugin(passportLocalMongoose);

const users = mongoose.model('users',userschema);

// use static authenticate method of model in LocalStrategy
passport.use(new LocalStrategy(users.authenticate()));

// use static serialize and deserialize of model for passport session support
passport.serializeUser(users.serializeUser());
passport.deserializeUser(users.deserializeUser());

/////////////////////////////////////////// Listen method /////////////////////////////////
app.listen("3000",function(err){
  if(!err)
  {
    console.log("Server hosted on 3000");
  }
});

////////////////////////////////////////// Main Page///////////////////////////////////////////////////

app.route("/")

.get(
  function(req,res)
  {
      res.render("home");
  }
);

app.get("/secrets",function(req,res){
  if(req.isAuthenticated())
  {
      res.render("secrets");
  }
  else{res.redirect("/");}
}
);

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});
///////////////////////////////////////// Register REST //////////////////////////////////////////////
app.route("/register")
.get(
  function(req,res)
  {
    res.render("register");
  }
)

.post(
  function(req,res)
  {
    users.register({username: req.body.username}, req.body.password, function(err, user) {
      if (err) {res.redirect('/');}
      else
      {
        passport.authenticate("local",{ failureFlash: 'Invalid username or password.', successFlash: 'Welcome!' })(req,res,function(){
        res.redirect('/secrets');
      });
      }
    });
});
// .post(
//   function(req,res)
//     {
//       bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//
//     // Store hash in your password DB.
//     const user1 = new users({
//       username : req.body.username,
//       password : hash
//     });
//
//     user1.save();
//
//     res.render("secrets");
//
//     });
//     }
// );

//////////////////////////////////////////// Login REST ///////////////////////////////////////////////
app.route("/login")
.get(
  function(req,res)
  {
    res.render("login");
  }
)

.post(function(req, res) {
    passport.authenticate('local',{failureFlash: 'Invalid username or password.'} ,function(err, user, info) {
      //console.log(user);
      if (user) {
        req.login(user, function(err) {
          console.log(user);
          if (!err) {
            res.redirect('/secrets');
          } else {
            res.redirect('/login');
          }
        });
      } else {
        res.redirect('/login');
      }
    })(req, res);
  });
// .post(
//   function(req,res)
//     {
//       users.findOne({username : req.body.username},function(err,founditem)
//       {
//
//         bcrypt.compare(req.body.password, founditem.password, function(err, result) {
//         // result == true
//         //if(founditem.password == md5(req.body.password) )
//         if(result == true)
//         {
//           res.render("secrets");
//         }
//         else
//         {
//           res.send("Wrong Credentials");
//         }
//
//         });
//
//       });
//     }
// );
