const http = require('http');

const payload = JSON.stringify({
  message: "Click to verify your ICICI account: https://retailnetbanking.icici.bank.in/login-page?ITM=verify&id=abc123"
});

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/analyze',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': payload.length
  }
};

const req = http.request(options, (res) => {
  let data = '';
  
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    const result = JSON.parse(data);
    console.log('\n✅ API Response:');
    console.log('  • isScamQuery:', result.isScamQuery);
    console.log('  • scamTypes:', result.analysis.scamTypes);
    console.log('  • confidence:', result.analysis.confidence + '%');
    console.log('  • localPhishingDetection:', !!result.localPhishingDetection ? 'PRESENT ✅' : 'MISSING ❌');
    
    if (result.localPhishingDetection) {
      console.log('  • URLs detected:', result.localPhishingDetection.urls.length);
      result.localPhishingDetection.urls.forEach(urlCheck => {
        console.log('    - URL:', urlCheck.url);
        console.log('    - Suspicious:', urlCheck.localAnalysis.isSuspicious);
        console.log('    - Score:', urlCheck.localAnalysis.suspiciousScore + '%');
        console.log('    - Patterns:', urlCheck.localAnalysis.detectedPatterns);
      });
      console.log('  • Suspicious Keywords:', result.localPhishingDetection.suspiciousKeywords);
    }
  });
});

req.on('error', (error) => {
  console.error('Error:', error);
});

req.write(payload);
req.end();
