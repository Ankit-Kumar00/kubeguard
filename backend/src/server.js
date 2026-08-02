const express = require("express");
const cors = require("cors");
require("dotenv").config();
const { connectDB } = require("./config/db");

const scannerRoutes = require("./routes/scannerRoutes");
const reportRoutes = require("./routes/reportRoutes");
const scanHistoryRoutes = require("./routes/scanHistoryRoutes");

const app = express();

app.use(cors());
app.use(express.json());

// Routes
app.use("/api", scannerRoutes);
app.use("/api", reportRoutes);
app.use("/api", scanHistoryRoutes);

app.get("/", (req, res) => {
  res.json({
    message: "KubeGuard API is running 🚀"
  });
});

const PORT = process.env.PORT || 5000;

// Connect Database, then Listen
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});