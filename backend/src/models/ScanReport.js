const mongoose = require("mongoose");

const ScanReportSchema = new mongoose.Schema({

    fileName: {
        type: String,
        required: true
    },

    findings: {
        type: [String],
        default: []
    },

    scannedAt: {
        type: Date,
        default: Date.now
    }

});

module.exports = mongoose.model("ScanReport", ScanReportSchema);