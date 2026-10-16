const userModel = require("../models/User");
const bcrypt = require("bcryptjs");
const { signInToken, sendEmail } = require("../config/auth");

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

module.exports = {
  createUser,
  userLogin,
};
