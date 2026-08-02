const PDFDocument = require("pdfkit");

function generateReport(res, reportData) {
  const { fileName, securityScore, severityCounts, findings, recommendations } = reportData;
  const doc = new PDFDocument({ margin: 50, size: "A4", bufferPages: true });

  // Stream directly to Express response
  doc.pipe(res);

  // Header/Banner Background
  doc.rect(0, 0, 595.28, 120).fill("#0f172a");

  // Logo & Title
  doc.fillColor("#38bdf8").fontSize(26).font("Helvetica-Bold").text("KubeGuard Report", 50, 40);
  doc.fillColor("#94a3b8").fontSize(11).font("Helvetica").text("Kubernetes Manifest Security Posture Assessment", 50, 75);

  // Metadata Panel
  doc.fillColor("#1e293b").fontSize(10);
  doc.font("Helvetica-Bold").text("Target File: ", 50, 150, { continued: true })
     .font("Helvetica").text(fileName || "raw_manifest.yaml");
  
  doc.font("Helvetica-Bold").text("Assessment Date: ", 50, 168, { continued: true })
     .font("Helvetica").text(new Date().toLocaleString());

  // Score Widget
  doc.rect(400, 140, 145, 68).fill("#1e1b4b");
  doc.fillColor("#818cf8").fontSize(9).font("Helvetica-Bold").text("SECURITY SCORE", 400, 150, { width: 145, align: "center" });

  let scoreColor = "#22c55e"; // Green
  if (securityScore < 50) scoreColor = "#ef4444"; // Red
  else if (securityScore < 70) scoreColor = "#f97316"; // Orange
  else if (securityScore < 90) scoreColor = "#eab308"; // Yellow

  doc.fillColor(scoreColor).fontSize(26).font("Helvetica-Bold").text(`${securityScore}/100`, 400, 168, { width: 145, align: "center" });

  // Severity Count Widgets
  const summaryY = 240;
  
  // Critical
  doc.rect(50, summaryY, 110, 45).fill("#7f1d1d");
  doc.fillColor("#fca5a5").fontSize(8).font("Helvetica-Bold").text("CRITICAL", 60, summaryY + 10);
  doc.fontSize(14).text((severityCounts.critical || 0).toString(), 60, summaryY + 23);

  // High
  doc.rect(170, summaryY, 110, 45).fill("#7c2d12");
  doc.fillColor("#ffedd5").fontSize(8).font("Helvetica-Bold").text("HIGH", 180, summaryY + 10);
  doc.fontSize(14).text((severityCounts.high || 0).toString(), 180, summaryY + 23);

  // Medium
  doc.rect(290, summaryY, 110, 45).fill("#713f12");
  doc.fillColor("#fef9c3").fontSize(8).font("Helvetica-Bold").text("MEDIUM", 300, summaryY + 10);
  doc.fontSize(14).text((severityCounts.medium || 0).toString(), 300, summaryY + 23);

  // Low
  doc.rect(410, summaryY, 110, 45).fill("#1e3a8a");
  doc.fillColor("#dbeafe").fontSize(8).font("Helvetica-Bold").text("LOW", 420, summaryY + 10);
  doc.fontSize(14).text((severityCounts.low || 0).toString(), 420, summaryY + 23);

  // Section: Hardening Recommendations
  let recY = 320;
  doc.fillColor("#0f172a").fontSize(13).font("Helvetica-Bold").text("Executive Recommendations", 50, recY);
  doc.rect(50, recY + 16, 495, 1.5).fill("#cbd5e1");
  
  recY += 28;
  recommendations.forEach(rec => {
    doc.fillColor("#334155").fontSize(9.5).font("Helvetica").text(`• ${rec}`, 60, recY, { width: 475 });
    recY += doc.heightOfString(`• ${rec}`, { width: 475 }) + 8;
  });

  // Section: Detailed Findings
  let itemY = recY + 20;
  doc.fillColor("#0f172a").fontSize(13).font("Helvetica-Bold").text("Detailed Security Findings", 50, itemY);
  doc.rect(50, itemY + 16, 495, 1.5).fill("#cbd5e1");
  
  itemY += 30;

  if (!findings || findings.length === 0) {
    doc.fillColor("#16a34a").fontSize(11).font("Helvetica-Oblique").text("No security violations detected in the inspected resources.", 60, itemY);
  } else {
    findings.forEach((finding, idx) => {
      // Prevent overflow, add page if near bottom
      if (itemY > 680) {
        doc.addPage();
        itemY = 50;
      }

      let badgeBg = "#64748b";
      let badgeFg = "#ffffff";
      const sev = finding.severity?.toLowerCase();
      if (sev === "critical") badgeBg = "#ef4444";
      else if (sev === "high") badgeBg = "#f97316";
      else if (sev === "medium") badgeBg = "#eab308";
      else if (sev === "low") badgeBg = "#3b82f6";

      const cardHeight = 80;
      // Draw background card
      doc.rect(50, itemY, 495, cardHeight).fill("#f8fafc");
      doc.rect(50, itemY, 4, cardHeight).fill(badgeBg); // border left

      // Header: Index, Category, Message
      doc.fillColor("#0f172a").fontSize(10.5).font("Helvetica-Bold").text(`${idx + 1}. [${finding.category}] ${finding.message}`, 65, itemY + 8, { width: 390 });
      
      // Severity Tag Widget (Right aligned)
      doc.rect(465, itemY + 8, 70, 16).fill(badgeBg);
      doc.fillColor(badgeFg).fontSize(8).font("Helvetica-Bold").text(finding.severity?.toUpperCase(), 465, itemY + 12, { width: 70, align: "center" });

      // Resource detail line
      doc.fillColor("#475569").fontSize(9).font("Helvetica").text("Resource: ", 65, itemY + 36, { continued: true })
         .font("Helvetica-Bold").fillColor("#0f172a").text(finding.resource || "Unknown");

      // Remediation recommendation line
      doc.fillColor("#16a34a").fontSize(9).font("Helvetica-Bold").text("Remediation: ", 65, itemY + 52, { continued: true })
         .font("Helvetica").fillColor("#334155").text(finding.remediation || "Check documentation.");

      itemY += cardHeight + 12;
    });
  }

  // Draw Page Footer for all pages
  const pages = doc.bufferedPageRange();
  for (let i = 0; i < pages.count; i++) {
    doc.switchToPage(i);
    
    doc.rect(50, 785, 495, 1).fill("#cbd5e1");
    doc.fillColor("#94a3b8").fontSize(7.5).font("Helvetica")
       .text(`KubeGuard Security Posture Assessment Report | Powered by KubeGuard Engine`, 50, 792, { align: "left", width: 350 });
    doc.text(`Page ${i + 1} of ${pages.count}`, 400, 792, { align: "right", width: 145 });
  }

  doc.end();
}

module.exports = {
  generateReport
};
