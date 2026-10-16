const express = require('express');

const router = express.Router();

const {
    createUser,
    userLogin,
    createUserJoi,
    userLoginJoi,
    createUserZod,
    userLoginZod,
    createUserExpressValidator,
    userLoginExpressValidator,
    signupValidationRules,
    loginValidationRules
} = require('../controller/userController');

router.post('/signup', createUser);
router.post('/signin', userLogin);

// Joi validation
router.post('/signup-joi', createUserJoi);
router.post('/signin-joi', userLoginJoi);

// Zod validation
router.post('/signup-zod', createUserZod);
router.post('/signin-zod', userLoginZod);

// express-validator (rules run as middleware before the controller)
router.post('/signup-ev', signupValidationRules, createUserExpressValidator);
router.post('/signin-ev', loginValidationRules, userLoginExpressValidator);

module.exports = router;
