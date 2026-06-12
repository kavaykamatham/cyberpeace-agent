const http = require('http');

const payload = JSON.stringify({
  message: "Verify your ICICI: https://retailnetbanking.icici.bank.in/login?ITM=check"
});

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/analyze',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': payload.length
  },
  timeout: 5000
};

const req = http.request(options, (res) => {
  let data = '';
  
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    try {
      const result = JSON.parse(data);
      console.log('✅ SUCCESS\n');
      console.log('Has localPhishingDetection:', 'localPhishingDetection' in result ? 'YES ✅' : 'NO ❌');
      console.log('URLs found:', result.extractedUrls.length);
      console.log('Is Scam:', result.isScamQuery);
      console.log('Scam Types:', result.analysis.scamTypes);
      if (result.localPhishingDetection) {
        console.log('Local Phishing Score:', result.localPhishingDetection.suspiciousScore);
      }
      process.exit(0);
    } catch (e) {
      console.error('Parse error:', e.message);
      process.exit(1);
    }
  });
});

req.on('error', (error) => {
  console.error('Connection error:', error.message);
  process.exit(1);
});

req.on('timeout', () => {
  console.error('Request timeout');
  req.destroy();
  process.exit(1);
});

req.write(payload);
req.end();
