const mongoose = require("mongoose");

const ScanReportSchema = new mongoose.Schema({
  fileName: {
    type: String,
    required: true
  },
  securityScore: {
    type: Number,
    required: true
  },
  severityCounts: {
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 }
  },
  findings: {
    type: Array,
    default: []
  },
  recommendations: {
    type: [String],
    default: []
  },
  scannedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("ScanReport", ScanReportSchema);