const express = require("express");
const cors = require("cors");
require("dotenv").config();

const scannerRoutes = require("./routes/scannerRoutes");
const reportRoutes = require("./routes/reportRoutes");

const app = express();

app.use(cors());
app.use(express.json());


// Routes
app.use("/api", scannerRoutes);
app.use("/api", reportRoutes);


app.get("/", (req, res) => {
    res.json({
        message: "KubeGuard API is running 🚀"
    });
});


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});