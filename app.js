const mongoose = require("mongoose");
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const userRoutes = require("./routes/UserRoutes");

require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use("/api", userRoutes);

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
