// Deliberate PDPL violations for testing
const userNationalId = req.body.nationalId;       // 1098765432
const iqama = req.body.iqama;                       // 2087654321
console.log("login", userNationalId, user.phone);   // PII in logs
fetch('https://vendor.io/track', { body: { nationalId } });
const config = { region: 'eu-west-1', db: 'patient_records' };  // cross-border
const apiKey = "sk_live_abc123def456ghijklmnop";    // hardcoded secret
axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
const hash = require('crypto').createHash('md5').update(password);
