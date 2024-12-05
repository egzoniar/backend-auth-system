const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");


const { users, therapists } = require("./database");

const server = express();
server.use(express.json());

server.use(cors());

const ACCESS_TOKEN_SECRET = "youraccesstokensecret";
const REFRESH_TOKEN_SECRET = "yourrefreshtokensecret";

const ACCESS_TOKEN_EXPIRATION = "10d";
const REFRESH_TOKEN_EXPIRATION = "10d";

const errHandler = (err) => {
  const {name, message} = JSON.parse(JSON.stringify(err));
  const error = {name, message};

  switch (name) {
    case "TokenExpiredError": 
    error.status = 401;
      break;
    default:
      error.status = 500;
  }

  return error;
};

const formatUser = (user) => {
  const { 
    password, 
    refreshToken, 
    iat, 
    exp,
    ...rest 
  } = user;
  return rest;
}

const userWithoutPassword = (user) => {
  const { 
    password, 
    firstName,
    lastName,
    ...rest 
  } = user;
  return rest;
}

// create an auth middleware
const auth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new Error("No authorization header");
    }

    const token = authHeader.split(" ")[1];
    const verifiedUser = jwt.verify(token, ACCESS_TOKEN_SECRET);

    if (!verifiedUser) {
      throw new Error("Invalid token");
    }

    const foundedUser = users.find((user) => user.id === verifiedUser.id);

    if (!foundedUser) {
      throw new Error("Invalid user");
    }

    req.user = formatUser(foundedUser);
    next();
  }
  catch(err) {
    console.log(err);
    const errObj = errHandler(err);
    res.status(errObj.status).json(errObj);
  }
}

// Add custom routes before JSON Server router
server.get("/me", auth, async (req, res) => {
  res.json(req.user);
});

server.get("/assigned-therapists", auth, async (req, res) => {
  const { assignedTherapists } = therapists;
  res.json({ therapists: assignedTherapists });
});

server.get("/therapists", auth, async (req, res) => {
  const { assignedTherapists, allTherapists } = therapists;

  const filteredTherapists = allTherapists.filter((therapist) => {
    const therapistId = therapist.id;
    const isAssigned = assignedTherapists.some((assignedTherapist) => assignedTherapist.id === therapistId);
    return !isAssigned;
  });

  res.json({ therapists: filteredTherapists });
});

server.post("/assign-therapists", auth, async (req, res) => {
  const { therapistIds } = req.body;
  const { allTherapists } = therapists;

  const assignedTherapists = allTherapists.filter((therapist) => therapistIds.includes(therapist.id));
  therapists.assignedTherapists = assignedTherapists;

  res.json({ assignedTherapists });
});

server.post("/signup", async (req, res) => {
    try {
      const reqUser = req.body;
      const { email, password } = reqUser;

      // Input validation
      if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
      }

      // Check if user already exists
      const user = users.find((user) => user.email === email);
      if (user) {
        return res.status(400).json({ error: "Email already exists" });
      }

      const id = users.length + 1;
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = { id, ...reqUser, password: hashedPassword };
      const accessToken = jwt.sign({id, email}, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRATION });
      const refreshToken = jwt.sign({id, email}, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION });
      newUser.refreshToken = refreshToken;

      users.push(newUser);

      const verifiedUser = await jwt.verify(accessToken, ACCESS_TOKEN_SECRET);

      res.json({ 
        id,
        ...userWithoutPassword(verifiedUser), 
        accessToken, 
        refreshToken 
      });
    } catch(err) {
      console.log(err);
      const errObj = errHandler(err);
      res.status(errObj.status).json(errObj);
    }
});

server.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Check if user exists
    const user = users.find((user) => user.email === email);
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const accessToken = jwt.sign({id: user.id, email: user.email}, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRATION });
    const refreshToken = jwt.sign({id: user.id, email: user.email}, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION });
    user.refreshToken = refreshToken;

    const verifiedUser = await jwt.verify(accessToken, ACCESS_TOKEN_SECRET);

    res.json({
      id: user.id,
      ...userWithoutPassword(verifiedUser), 
      accessToken, 
      refreshToken 
    });
  } catch(err) {
      const errObj = errHandler(err);
      res.status(errObj.status).json(errObj);
  }
});

server.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    // Input validation
    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }

    const foundedUser = users.find((user) => user.refreshToken === refreshToken);
    if (!foundedUser) {
      return res.status(400).json({ error: "Invalid refresh token" });
    }

    const user = await jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    const accessToken = jwt.sign({id: foundedUser.id, email: user.email}, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRATION });
    res.json({ accessToken }); 
  }
  catch(err) {
    const errObj = errHandler(err);
    res.status(errObj.status).json(errObj);
  }
});

server.delete("/logout", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    // Input validation
    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }

    const foundedUser = users.find((user) => user.refreshToken === refreshToken);
    if (!foundedUser) {
      return res.status(400).json({ error: "Invalid refresh token" });
    }

    delete foundedUser.refreshToken;
    res.sendStatus(204);
  }
  catch(err) {
    const errObj = errHandler(err);
    res.status(errObj.status).json(errObj);
  }
});

server.listen(4000, () => {
  console.log('JSON Server is running on port 4000')
});