const { exec } = require("child_process");
const path = require("path");

function runScanner(filePath) {
  return new Promise((resolve, reject) => {
    const scannerPath = path.join(
      __dirname,
      "../../../security-scanners/yaml-scanner/scanner.py"
    );

    // Escape quotes in path for safety
    const command = `python "${scannerPath}" "${filePath}"`;

    exec(command, (error, stdout, stderr) => {
      if (error) {
        console.error("Scanner execution error:", stderr || error.message);
        reject(new Error(stderr || error.message));
        return;
      }

      try {
        const parsed = JSON.parse(stdout.trim());
        resolve(parsed);
      } catch (err) {
        console.error("Failed to parse scanner output:", stdout);
        reject(new Error("Scanner returned invalid JSON output"));
      }
    });
  });
}

module.exports = {
  runScanner,
};