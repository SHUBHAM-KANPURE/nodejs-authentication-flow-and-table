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

module.exports = {
  joiSignupSchema,
  joiLoginSchema,
  zodSignupSchema,
  zodLoginSchema,
  signupValidationRules,
  loginValidationRules,
  getValidationErrors,
};
