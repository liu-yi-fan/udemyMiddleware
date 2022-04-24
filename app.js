require("dotenv").config();
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const flash = require("connect-flash");
const bodyParser = require("body-parser");
const User = require("./models/user");
const bcrypt = require("bcrypt");
const saltRounds = 10;

app.set("view engine", "ejs");
app.use(cookieParser(process.env.SECRET));
app.use(
  session({
    secret: process.env.SECRET,
    resave: false, //一些設定，資源包有詳解
    saveUninitialized: false,
  })
);
app.use(flash());
app.use(bodyParser.urlencoded({ extended: true }));

const requireLogin = (req, res,  next) => {
  if (!req.session.inVerified == true){
    res.redirect("login");
  } else {
    next();
  }
};

mongoose
  .connect("mongodb://localhost:27017/test", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to mongodb.");
  })
  .catch((e) => {
    console.log(e);
  });

app.get("/", (req, res) => {
  res.send("Home page.");
});

app.get("/secret", requireLogin, (req, res) => {
  res.render("secret");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res, next) => {
  let { username, password } = req.body;
  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      bcrypt.compare(password, foundUser.password, (err, result) => {
        if (err) {
          next(err);
        }
  
        if (result === true) {
          req.session.inVerified = true; //成功登入一次之後會儲存進session，關掉頁面再進/secret的路徑就不用再登入
          res.redirect("secret");
        } else {
          res.send("Username or password not correct.");
        }
      });
    } else {
      res.send("Username or password not correct.");
    }
  } catch (e) {
    next(e);
  }
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res, next) => {
  let { username, password } = req.body;

  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      res.send("Username has been taken.");
    } else {
      bcrypt.genSalt(saltRounds, (err, salt) => {  
        if (err) {
          next(err);
        }
        console.log(salt);
        bcrypt.hash(password, salt, (err, hash) => {
          if (err) {
            next(err);
          }
    
          console.log(hash);
          let newUser = new User({ username, password: hash });
          try {
            newUser
              .save()
              .then(() => {
                res.send("Data has been saved.");
              })
              .catch((e) => {
                res.send("Error!!");
              });
          } catch (err) {
            next(err);
          }
        });
      });
    }
  } catch (err) {
    next(err);
  }
});

app.get("/*", (req, res) => {
  res.status(404).send("404 Page not found.");
});

// error handler
app.use((err, req, res, next) => {
  console.log(err);
  res.status(500).send("Something is broken. We will fix it soon.");
});

app.listen(3000, () => {
  console.log("Server running on port 3000.");
});
