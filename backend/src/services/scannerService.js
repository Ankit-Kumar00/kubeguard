const { exec } = require("child_process");

function runScanner(filePath) {

    return new Promise((resolve, reject) => {

        exec(
            `python ../security-scanners/yaml-scanner/scanner.py ${filePath}`,
            (error, stdout, stderr) => {

                if (error) {
                    reject(stderr);
                    return;
                }

                resolve(stdout);
            }
        );

    });

}

module.exports = {
    runScanner
};