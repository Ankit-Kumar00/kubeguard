function calculateSecurity(findings) {

    let critical = 0;
    let high = 0;
    let medium = 0;

    findings.forEach(issue => {

        if (issue.startsWith("Critical"))
            critical++;

        else if (issue.startsWith("High"))
            high++;

        else if (issue.startsWith("Medium"))
            medium++;

    });

    let score = 100;

    score -= critical * 30;
    score -= high * 20;
    score -= medium * 10;

    if (score < 0)
        score = 0;

    return {

        score,

        critical,

        high,

        medium,

        total: findings.length

    };

}

module.exports = {
    calculateSecurity
};