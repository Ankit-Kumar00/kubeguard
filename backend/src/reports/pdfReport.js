const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");

function generateReport(findings) {
    return new Promise((resolve, reject) => {

        const fileName = path.join(
            __dirname,
            "../../reports",
            `KubeGuard_Report_${Date.now()}.pdf`
        );

        const doc = new PDFDocument();

        const stream = fs.createWriteStream(fileName);

        doc.pipe(stream);

        doc.fontSize(22).text("KubeGuard Security Report");

        doc.moveDown();

        doc.fontSize(14).text("Kubernetes YAML Security Assessment");

        doc.moveDown();

        findings.forEach((issue, index) => {
            doc.text(`${index + 1}. ${issue}`);
        });

        doc.end();

        stream.on("finish", () => {
            resolve(fileName);
        });

        stream.on("error", (err) => {
            reject(err);
        });

    });
}

module.exports = {
    generateReport
};
