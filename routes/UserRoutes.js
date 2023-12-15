const express = require("express");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/UserSchema");
const Budget = require("../models/BudgetSchema");

const router = express.Router();

const invalidatedTokens = new Set();

const handleServerError = (res, error) => {
  console.error(error);
  return res
    .status(500)
    .json({ error: error.message || "Internal server error" });
};

const authenticateToken = async (req, res, next) => {
  const token = req.cookies.token;

  if (!token || invalidatedTokens.has(token)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const user = await jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    console.log("Token verification error:", err);
    return res.status(403).json({ error: "Invalid token" });
  }
};

const registerValidation = [
  body("userName")
    .trim()
    .isLength({ min: 1 })
    .withMessage("Username is required")
    .custom(async (value) => {
      if (await User.findOne({ userName: value })) {
        throw new Error("Username is already taken");
      }

      if (!/^[A-Z]/.test(value)) {
        throw new Error("Username must start with a capital letter");
      }

      return true;
    }),
  body("email").isEmail().withMessage("Invalid email address"),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long")
    .matches(/\d/)
    .withMessage("Password must contain at least one number"),
];

router.post("/register", registerValidation, async (req, res) => {
  try {
    const { userName, password, email } = req.body;

    if (!userName || !password || !email) {
      return res.status(400).json({
        error: "Registration failed",
        message: "Missing required fields",
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    if (await User.findOne({ $or: [{ userName }, { email }] })) {
      return res.status(400).json({
        error: "Registration failed",
        message: "Username or email already exists",
        errorCode: "DUPLICATE_DATA",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      userName,
      password: hashedPassword,
      email,
      status: "Registered",
    });

    await newUser.save();

    return res
      .status(201)
      .json({ message: "User registered successfully", user: newUser });
  } catch (error) {
    handleServerError(res, error);
  }
});

const loginValidation = [
  body("userName").trim().notEmpty().withMessage("Username is required"),
  body("password").trim().notEmpty().withMessage("Password is required"),
];

router.post("/login", loginValidation, async (req, res) => {
  try {
    const { userName, password } = req.body;

    if (!userName || !password) {
      return res.status(400).json({
        error: "Login failed",
        message: "Missing required fields",
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const user = await User.findOne({ userName });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (user.status === "Deactivated") {
      return res.status(401).json({
        error: "Account deactivated",
        message: "Can't access deactivated account",
      });
    }
    await User.findByIdAndUpdate(user._id, { status: "Active" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000,
    });

    return res.status(200).json({ message: "Login successful" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/logout", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    await User.findByIdAndUpdate(userId, { status: "Inactive" });

    const token = req.cookies.token;
    invalidatedTokens.add(token);

    res.clearCookie("token").status(200).json({ message: "Logout successful" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/deactivate", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        error: "Invalid request",
        message: "Password is required for account deactivation",
      });
    }

    const user = await User.findById(userId);
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Invalid password for account deactivation",
      });
    }

    await User.findByIdAndUpdate(userId, { status: "Deactivated" });

    const token = req.cookies.token;
    invalidatedTokens.add(token);

    res.clearCookie("token");

    return res
      .status(200)
      .json({ message: "Account deactivated successfully" });
  } catch (error) {
    handleServerError(res, error);
  }
});

const forgotPasswordValidation = [
  body("userName").trim().notEmpty().withMessage("Username is required"),
  body("email").isEmail().withMessage("Invalid email address"),
  body("newPassword")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long")
    .matches(/\d/)
    .withMessage("Password must contain at least one number"),
];

router.post("/forgot-password", forgotPasswordValidation, async (req, res) => {
  try {
    const { userName, email, newPassword } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const user = await User.findOne({ userName, email });

    if (!user) {
      return res.status(404).json({
        error: "User not found",
        message: "No user found with the provided username and email",
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(user._id, {
      password: hashedPassword,
      status: "Updating Credentials",
    });

    user.password = hashedPassword;

    await user.save();

    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.get("/budgets", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const budgets = await Budget.find({ userId });
    res.status(200).json(budgets);
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/budgets", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { category, subcategory, paymentType, moneyAmount, isFavorite } =
      req.body;
    const newBudget = new Budget({
      userId,
      category,
      subcategory,
      paymentType,
      moneyAmount,
      isFavorite,
    });
    await newBudget.save();
    res
      .status(201)
      .json({ message: "Budget added successfully", budget: newBudget });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.put("/budgets/:budgetId", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const budgetId = req.params.budgetId;
    const { category, subcategory, paymentType, moneyAmount, isFavorite } =
      req.body;
    const updatedBudget = await Budget.findOneAndUpdate(
      { _id: budgetId, userId },
      { category, subcategory, paymentType, moneyAmount, isFavorite },
      { new: true }
    );
    if (!updatedBudget) {
      return res.status(404).json({ error: "Budget not found" });
    }
    res
      .status(200)
      .json({ message: "Budget updated successfully", budget: updatedBudget });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.delete("/budgets/:budgetId", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const budgetId = req.params.budgetId;
    const deletedBudget = await Budget.findOneAndDelete({
      _id: budgetId,
      userId,
    });
    if (!deletedBudget) {
      return res.status(404).json({ error: "Budget not found" });
    }
    res
      .status(200)
      .json({ message: "Budget deleted successfully", budget: deletedBudget });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.patch(
  "/budgets/:budgetId/favourite",
  authenticateToken,
  async (req, res) => {
    try {
      const userId = req.user.userId;
      const budgetId = req.params.budgetId;
      const { isFavorite } = req.body;
      const updatedBudget = await Budget.findOneAndUpdate(
        { _id: budgetId, userId },
        { isFavorite },
        { new: true }
      );
      if (!updatedBudget) {
        return res.status(404).json({ error: "Budget not found" });
      }
      res.status(200).json({
        message: "Budget updated successfully",
        budget: updatedBudget,
      });
    } catch (error) {
      handleServerError(res, error);
    }
  }
);

router.get("/budgets/filter", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { category, subcategory } = req.query;

    const filter = { userId };
    if (category) {
      filter.category = category;
    }
    if (subcategory) {
      filter.subcategory = subcategory;
    }

    const budgets = await Budget.find(filter);
    res.status(200).json(budgets);
  } catch (error) {
    handleServerError(res, error);
  }
});

module.exports = router;

module.exports = router;
