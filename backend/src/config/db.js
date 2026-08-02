const mongoose = require("mongoose");

let isDbConnected = false;

const connectDB = async () => {
  if (!process.env.MONGO_URI) {
    console.warn("WARNING: MONGO_URI environment variable is not defined. Running in offline/localStorage mode.");
    isDbConnected = false;
    return false;
  }
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 3000
    });
    isDbConnected = true;
    console.log("MongoDB Connected Successfully");
    return true;
  } catch (error) {
    console.error("MongoDB Connection Failed:", error.message);
    console.warn("KubeGuard will run in offline/localStorage mode.");
    isDbConnected = false;
    return false;
  }
};

const getDbStatus = () => isDbConnected;

module.exports = {
  connectDB,
  getDbStatus
};
