const express = require("express");
const { generateReport } = require("../reports/pdfReport");

const router = express.Router();


router.post("/generate-report", async (req,res)=>{

    try{

        const findings = req.body.findings;


        const file = await generateReport(findings);


        const path = require("path");

res.download(file, path.basename(file));


    }
    catch(error){

        res.status(500).json({
            error:error.message
        });

    }

});


module.exports = router;