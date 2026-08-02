const express = require("express");
const ScanReport = require("../models/ScanReport");
const { getDbStatus } = require("../config/db");

const router = express.Router();

// Retrieve scan history
router.get("/history", async (req, res) => {
  try {
    if (!getDbStatus()) {
      return res.json({
        success: true,
        dbConnected: false,
        history: [] // Fallback to empty if DB is offline
      });
    }

    // Return scans ordered by latest scanned first
    const scans = await ScanReport.find().sort({ scannedAt: -1 });
    return res.json({
      success: true,
      dbConnected: true,
      history: scans
    });
  } catch (error) {
    console.error("Fetch history failed:", error.message);
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// Delete scan report
router.delete("/history/:id", async (req, res) => {
  try {
    if (!getDbStatus()) {
      return res.status(503).json({
        success: false,
        message: "Database is not connected"
      });
    }

    const { id } = req.params;
    await ScanReport.findByIdAndDelete(id);

    return res.json({
      success: true,
      message: "Report deleted successfully"
    });
  } catch (error) {
    console.error("Delete report failed:", error.message);
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

module.exports = router;
