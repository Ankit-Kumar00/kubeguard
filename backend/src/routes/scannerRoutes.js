const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { runScanner } = require("../services/scannerService");
const { getDbStatus } = require("../config/db");
const ScanReport = require("../models/ScanReport");

const router = express.Router();

// Ensure uploads folder exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const upload = multer({
  dest: "uploads/"
});

function calculateSeverity(findings) {
  const severity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  findings.forEach(item => {
    const level = item.severity?.toLowerCase();
    if (severity[level] !== undefined) {
      severity[level]++;
    }
  });

  return severity;
}

function calculateScore(severity) {
  let score = 100;
  score -= (severity.critical || 0) * 25;
  score -= (severity.high || 0) * 15;
  score -= (severity.medium || 0) * 5;
  score -= (severity.low || 0) * 2;

  return Math.max(score, 0);
}

function generateRecommendations(severity) {
  const recommendations = [];
  if (severity.critical > 0) {
    recommendations.push(
      "Immediately remediate Critical vulnerabilities (e.g., privileged mode or host PID sharing) as they allow host-level access."
    );
  }
  if (severity.high > 0) {
    recommendations.push(
      "Fix High severity configuration flaws, especially container root access and privilege escalation."
    );
  }
  if (severity.medium > 0) {
    recommendations.push(
      "Apply security hardening: enable read-only root filesystems, configure seccomp profiles, and set CPU/Memory limits."
    );
  }
  if (
    severity.critical === 0 &&
    severity.high === 0 &&
    severity.medium === 0
  ) {
    recommendations.push(
      "Configuration looks secure and follows best practices. Keep monitoring continuously."
    );
  }
  return recommendations;
}

router.post("/scan-yaml", upload.single("file"), async (req, res) => {
  let tempFilePath = null;
  let fileNameText = "pasted_manifest.yaml";

  try {
    if (req.file) {
      tempFilePath = req.file.path;
      fileNameText = req.file.originalname;
    } else if (req.body && req.body.yaml) {
      // Create a temporary file for pasted YAML
      tempFilePath = path.join("uploads", `paste_${Date.now()}.yaml`);
      fs.writeFileSync(tempFilePath, req.body.yaml);
      fileNameText = req.body.fileName || "raw_editor_scan.yaml";
    } else {
      return res.status(400).json({
        success: false,
        message: "No YAML file uploaded or text provided"
      });
    }

    const findings = await runScanner(tempFilePath);
    const severity = calculateSeverity(findings);
    const securityScore = calculateScore(severity);
    const recommendations = generateRecommendations(severity);

    // Clean up temporary file
    if (tempFilePath) {
      fs.unlink(tempFilePath, (err) => {
        if (err) console.error("Error deleting temp file:", err.message);
      });
    }

    const reportData = {
      fileName: fileNameText,
      securityScore,
      severityCounts: severity,
      findings,
      recommendations,
      scannedAt: new Date()
    };

    // Save to database if connected
    if (getDbStatus()) {
      try {
        const savedReport = await ScanReport.create(reportData);
        return res.json({
          success: true,
          id: savedReport._id,
          ...reportData
        });
      } catch (dbErr) {
        console.error("Database save failed:", dbErr.message);
        return res.json({
          success: true,
          ...reportData
        });
      }
    }

    // Default response if DB is offline
    return res.json({
      success: true,
      ...reportData
    });

  } catch (error) {
    console.error("Scan API Error:", error.message);
    if (tempFilePath && fs.existsSync(tempFilePath)) {
      try {
        fs.unlinkSync(tempFilePath);
      } catch (unlinkErr) {
        // ignore
      }
    }
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

module.exports = router;