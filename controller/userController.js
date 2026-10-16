const userModel = require("../models/User");
const bcrypt = require("bcryptjs");
const { signInToken, sendEmail } = require("../config/auth");
const Joi = require("joi");
const { z } = require("zod");
const { body, validationResult } = require("express-validator");

// ---------- Joi schemas ----------
const joiSignupSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const joiLoginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

// ---------- express-validator rules (used as route middleware) ----------
const signupValidationRules = [
  body("username").isString().isLength({ min: 3, max: 30 }),
  body("email").isEmail(),
  body("password").isLength({ min: 6 }),
];

const loginValidationRules = [
  body("email").isEmail(),
  body("password").notEmpty(),
];

// Returns a list of error messages if validation failed, otherwise null
const getValidationErrors = (req) => {
  const result = validationResult(req);
  if (result.isEmpty()) return null;
  return result.array().map((e) => `${e.path}: ${e.msg}`);
};

// ---------- Zod schemas ----------
const zodSignupSchema = z.object({
  username: z.string().min(3).max(30),
  email: z.string().email(),
  password: z.string().min(6),
});

const zodLoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const createUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!email || !password)
      return res.status(401).send({
        message: "Email and password is required !",
      });

    const isAdded = await userModel.findOne({ email: email });

    if (isAdded) {
      return res.status(401).send({
        message: "User already exist with this email",
      });
    } else {

      const newUser = new userModel({
        username: username,
        email,
        password: bcrypt.hashSync(password),
      });
      await newUser.save();
      let FrontendPort = process.env.FRONTEND_PORT;

      const file = "./views/email_invitation.ejs";
      const subject = "Welcome to Our Site";
      const message = {
        email: email,
        pass: password,
        FrontendPort: FrontendPort,
      };
      sendEmail(email, password, file, subject, message);
      return res
        .status(200)
        .send({ msg: "Please check your email to login your account or login!" });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

const userLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(401).send({
        message: "Email and password is required !",
      });

    const user = await userModel.findOne({ email: email });

    if (user && user.password && bcrypt.compareSync(password, user.password)) {
      const token = signInToken(user);
      return res.send({
        token,
        _id: user?._id,
        username: user?.username,
        email: user?.email,
        message: "You are logged in",
      });
    } else {
      return res.status(401).send({
        message: "Invalid user or password !",
      });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

// Same as createUser, but input is validated with Joi
const createUserJoi = async (req, res) => {
  try {
    // abortEarly: false -> collect all errors, not just the first one
    const { error, value } = joiSignupSchema.validate(req.body, {
      abortEarly: false,
    });

    if (error)
      return res.status(400).send({
        message: "Validation failed",
        errors: error.details.map((d) => d.message),
      });

    const { username, email, password } = value;

    const isAdded = await userModel.findOne({ email: email });

    if (isAdded) {
      return res.status(401).send({
        message: "User already exist with this email",
      });
    } else {
      const newUser = new userModel({
        username: username,
        email,
        password: bcrypt.hashSync(password),
      });
      await newUser.save();
      let FrontendPort = process.env.FRONTEND_PORT;

      const file = "./views/email_invitation.ejs";
      const subject = "Welcome to Our Site";
      const message = {
        email: email,
        pass: password,
        FrontendPort: FrontendPort,
      };
      sendEmail(email, password, file, subject, message);
      return res
        .status(200)
        .send({ msg: "Please check your email to login your account or login!" });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

// Same as userLogin, but input is validated with Joi
const userLoginJoi = async (req, res) => {
  try {
    const { error, value } = joiLoginSchema.validate(req.body, {
      abortEarly: false,
    });

    if (error)
      return res.status(400).send({
        message: "Validation failed",
        errors: error.details.map((d) => d.message),
      });

    const { email, password } = value;

    const user = await userModel.findOne({ email: email });

    if (user && user.password && bcrypt.compareSync(password, user.password)) {
      const token = signInToken(user);
      return res.send({
        token,
        _id: user?._id,
        username: user?.username,
        email: user?.email,
        message: "You are logged in",
      });
    } else {
      return res.status(401).send({
        message: "Invalid user or password !",
      });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

// Same as createUser, but input is validated with Zod
const createUserZod = async (req, res) => {
  try {
    // safeParse never throws; returns { success, data } or { success, error }
    const result = zodSignupSchema.safeParse(req.body);

    if (!result.success)
      return res.status(400).send({
        message: "Validation failed",
        errors: result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
      });

    const { username, email, password } = result.data;

    const isAdded = await userModel.findOne({ email: email });

    if (isAdded) {
      return res.status(401).send({
        message: "User already exist with this email",
      });
    } else {
      const newUser = new userModel({
        username: username,
        email,
        password: bcrypt.hashSync(password),
      });
      await newUser.save();
      let FrontendPort = process.env.FRONTEND_PORT;

      const file = "./views/email_invitation.ejs";
      const subject = "Welcome to Our Site";
      const message = {
        email: email,
        pass: password,
        FrontendPort: FrontendPort,
      };
      sendEmail(email, password, file, subject, message);
      return res
        .status(200)
        .send({ msg: "Please check your email to login your account or login!" });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

// Same as userLogin, but input is validated with Zod
const userLoginZod = async (req, res) => {
  try {
    const result = zodLoginSchema.safeParse(req.body);

    if (!result.success)
      return res.status(400).send({
        message: "Validation failed",
        errors: result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`),
      });

    const { email, password } = result.data;

    const user = await userModel.findOne({ email: email });

    if (user && user.password && bcrypt.compareSync(password, user.password)) {
      const token = signInToken(user);
      return res.send({
        token,
        _id: user?._id,
        username: user?.username,
        email: user?.email,
        message: "You are logged in",
      });
    } else {
      return res.status(401).send({
        message: "Invalid user or password !",
      });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

// Same as createUser, but input is validated with express-validator
// (rules run as middleware in the route, see signupValidationRules)
const createUserExpressValidator = async (req, res) => {
  try {
    const errors = getValidationErrors(req);

    if (errors)
      return res.status(400).send({
        message: "Validation failed",
        errors,
      });

    const { username, email, password } = req.body;

    const isAdded = await userModel.findOne({ email: email });

    if (isAdded) {
      return res.status(401).send({
        message: "User already exist with this email",
      });
    } else {

      const newUser = new userModel({
        username: username,
        email,
        password: bcrypt.hashSync(password),
      });
      await newUser.save();
      let FrontendPort = process.env.FRONTEND_PORT;

      const file = "./views/email_invitation.ejs";
      const subject = "Welcome to Our Site";
      const message = {
        email: email,
        pass: password,
        FrontendPort: FrontendPort,
      };
      sendEmail(email, password, file, subject, message);
      return res
        .status(200)
        .send({ msg: "Please check your email to login your account or login!" });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

// Same as userLogin, but input is validated with express-validator
// (rules run as middleware in the route, see loginValidationRules)
const userLoginExpressValidator = async (req, res) => {
  try {
    const errors = getValidationErrors(req);

    if (errors)
      return res.status(400).send({
        message: "Validation failed",
        errors,
      });

    const { email, password } = req.body;

    const user = await userModel.findOne({ email: email });

    if (user && user.password && bcrypt.compareSync(password, user.password)) {
      const token = signInToken(user);
      return res.send({
        token,
        _id: user?._id,
        username: user?.username,
        email: user?.email,
        message: "You are logged in",
      });
    } else {
      return res.status(401).send({
        message: "Invalid user or password !",
      });
    }
  } catch (error) {
    return res.status(500).send(error.message || error);
  }
};

module.exports = {
  createUser,
  userLogin,
  createUserJoi,
  userLoginJoi,
  createUserZod,
  userLoginZod,
  createUserExpressValidator,
  userLoginExpressValidator,
  signupValidationRules,
  loginValidationRules,
};
