const express = require("express");
const { generateReport } = require("../reports/pdfReport");

const router = express.Router();

router.post("/generate-report", async (req, res) => {
  try {
    const reportData = req.body;

    if (!reportData || !reportData.findings || !Array.isArray(reportData.findings)) {
      return res.status(400).json({
        success: false,
        message: "Invalid findings data"
      });
    }

    // Set correct response headers for streaming PDF
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="KubeGuard_Report_${Date.now()}.pdf"`
    );

    // Stream PDF directly to Express response
    generateReport(res, reportData);

  } catch (error) {
    console.error("PDF generation endpoint failed:", error.message);
    if (!res.headersSent) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
});

module.exports = router;
