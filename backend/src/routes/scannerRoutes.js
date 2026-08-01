const express = require("express");
const multer = require("multer");
const { runScanner } = require("../services/scannerService");

const router = express.Router();

const upload = multer({
    dest: "uploads/"
});


router.post("/scan-yaml", upload.single("file"), async (req, res) => {

    try {

        console.log("Request received");

        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: "No file uploaded"
            });
        }

        console.log("Uploaded file:", req.file.path);

        const result = await runScanner(req.file.path);

        console.log("Scanner result:", result);

        res.json({
            success: true,
            result: result
        });

    } catch (error) {

        console.log("ERROR:", error);

        res.status(500).json({
            success: false,
            error: error.toString()
        });

    }

});


module.exports = router;