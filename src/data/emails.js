import { CATEGORIES } from './templates.js'

export const PEOPLE = {
  manager: { name: 'Marcus Webb', role: 'SOC Manager', addr: 'm.webb@northbridgefinancial.com' },
  l2: { name: 'Elena Rodriguez', role: 'L2 Analyst', addr: 'e.rodriguez@northbridgefinancial.com' },
  intel: { name: 'Dave Okafor', role: 'Threat Intelligence', addr: 'd.okafor@northbridgefinancial.com' },
  itops: { name: 'IT Operations', role: 'Automated Notice', addr: 'it-ops-noreply@northbridgefinancial.com' },
}

let emailUid = 0
function email(from, subject, body, kind = 'info') {
  emailUid += 1
  return { id: `em-${Date.now()}-${emailUid}`, from, subject, body, kind, read: false, receivedAt: Date.now() }
}

export function briefingEmail() {
  return email(PEOPLE.manager, 'Welcome to the night shift — read this first', `Welcome aboard. You're covering the L1 triage queue solo tonight, so here's the short version of the job.

For EVERY alert in the queue you make three calls:

1. VERDICT — is it a TRUE POSITIVE (real malicious/policy-violating activity) or a FALSE POSITIVE (benign activity that tripped a rule)? Read the logs and the enrichment panel before deciding. Volume, source, timing, and business context usually settle it.

2. CATEGORY — if it's a true positive, classify the attack type. Getting this right matters: L2 routes incidents by category.

3. ACTION — Escalate or Close.
   • ESCALATE anything confirmed malicious that succeeded or is still active: compromised accounts, beacons, movement between hosts, data that actually left, privilege changes outside process.
   • CLOSE (with documentation) attacks that our controls fully blocked with zero sign of success — dropped scans, quarantined mail, WAF-blocked injection, locked-out brute force. Escalating blocked noise buries the L2 team.
   • False positives are always closed.

One more thing: the moment you open an alert its SLA clock starts. Our targets are tight tonight — if the clock runs out the alert auto-fails, so don't open something you're not ready to work.

I review the shift stats in the morning. Elena (L2) will ping you if something you closed comes back to bite us, or if you flood her queue with noise.

Good luck.

— Marcus Webb
SOC Manager, Northbridge Financial`, 'briefing')
}

export function mistakeEmail(alert, res) {
  const catName = CATEGORIES[alert.category]
  let what
  if (res.slaBreached) {
    what = `The SLA clock ran out on ${alert.number} ("${alert.title}") before you resolved it. An untriaged ${alert.verdict === 'tp' ? 'REAL incident' : 'alert'} sat in the queue past its deadline — that's an automatic miss on our metrics, and if it had been live attacker activity we'd have lost the response window.`
  } else {
    const parts = []
    if (!res.verdictOk) {
      parts.push(alert.verdict === 'tp'
        ? `you closed ${alert.number} ("${alert.title}") as a false positive — it was a REAL ${catName}. We caught it on re-review, but that's the kind of miss that turns into a breach report.`
        : `you flagged ${alert.number} ("${alert.title}") as a true positive — it was benign. I spent 40 minutes running down what turned out to be ${catName.toLowerCase()}-shaped noise.`)
    } else {
      if (!res.categoryOk) parts.push(`you called ${alert.number} ("${alert.title}") a ${CATEGORIES[res.category] || 'different attack type'}, but the evidence points to ${catName}. Misclassification routes the incident to the wrong response playbook.`)
      if (!res.actionOk) parts.push(alert.correctAction === 'escalate'
        ? `you closed ${alert.number} ("${alert.title}") instead of escalating. There were active-compromise indicators in that one — closing it left an attacker with room to operate.`
        : `you escalated ${alert.number} ("${alert.title}") — it was fully blocked with no success indicators. Escalations like that bury the queue; blocked attempts get documented and closed.`)
    }
    what = 'Quick feedback: ' + parts.join(' Also, ')
  }
  return email(PEOPLE.l2, `Re: ${alert.number} — review notes`, `${what}

What the evidence showed:
${alert.explanation}

No drama — everyone eats one of these occasionally. Just tighten up the next one.

— Elena`, 'mistake')
}

export function praiseEmail(streak) {
  return email(PEOPLE.manager, `Nice run on the queue`, `Just glanced at the live board — ${streak} clean resolutions in a row, verdict, classification and routing all correct. That's exactly the signal-from-noise discipline we hired for.

Keep it going. The queue doesn't get easier from here.

— Marcus`, 'praise')
}

export function tier2Email() {
  return email(PEOPLE.intel, 'Heads up — activity picking up tonight', `FYI from the intel side: we're seeing elevated activity across the sector tonight — a commodity malspam wave plus at least one actor doing targeted work against financial orgs.

Practical impact for your queue: expect alerts where the SIEM severity doesn't match reality, and benign ops work (patching, backups, VPN weirdness) mixed in with the real thing. Read the enrichment before you trust the headline.

— Dave
Threat Intel`, 'info')
}

export function tier3Email() {
  return email(PEOPLE.l2, 'Late-shift queue — trust the evidence, not the severity', `The stuff landing in the queue after 2 AM is the tricky third of the shift. Two things I wish someone had told me at L1:

1. The SIEM's severity score is a guess. Some of the worst incidents I've worked arrived as LOW — and some CRITICAL banners turn out to be an authorized pentest. The evidence decides, not the label.

2. When something looks like admin work, verify the paper trail: change ticket, PAM checkout, schedule, scope. Attackers don't file change requests — but they do hide in maintenance windows.

Almost through the night. Stay sharp.

— Elena`, 'info')
}

export function coffeeEmail() {
  return email(PEOPLE.itops, 'Facilities notice: coffee machine (3rd floor) back online', `The espresso machine on floor 3 has been repaired and returned to service. The incident (INC-81244, "hot water dispensing anomaly, brown liquid absent") is now closed.

We thank the night-shift SOC for their patience and for NOT escalating this to Major Incident status this time.

— IT Operations`, 'info')
}

export function finalEmail(accuracy, stats) {
  const pct = Math.round(accuracy * 100)
  const line = `Shift stats: ${stats.resolved} alerts triaged, ${stats.correct} fully correct (${pct}%), ${stats.slaBreaches} SLA ${stats.slaBreaches === 1 ? 'breach' : 'breaches'}.`
  if (accuracy >= 1) {
    return email(PEOPLE.manager, 'Shift review — and some news (open me)', `I've just gone through the overnight board and I had to double-check the numbers.

${line}

A perfect shift. Every verdict right, every incident classified and routed correctly, nothing left to rot in the queue. I've been running this SOC for nine years and I can count the flawless nights on one hand.

I spoke with the director this morning: effective next rotation, you're promoted to L2 ANALYST. Elena will start your incident-response onboarding next week. Congratulations — genuinely earned.

— Marcus Webb
SOC Manager, Northbridge Financial`, 'final-promotion')
  }
  if (accuracy >= 0.75) {
    return email(PEOPLE.manager, 'Shift review — solid night', `Morning. I've reviewed the overnight board.

${line}

That's a solid shift. A few calls went the wrong way — Elena's notes are in your inbox, read them — but you kept the queue moving, caught the things that mattered, and didn't drown L2 in noise. That's the job.

Keep tightening up the misses and L2 is a realistic conversation in a couple of quarters. See you tonight.

— Marcus Webb
SOC Manager, Northbridge Financial`, 'final-pass')
  }
  return email(PEOPLE.manager, 'Shift review — please see me before you leave', `I've reviewed the overnight board and I'll be direct.

${line}

Real incidents were closed as noise, benign activity was escalated, and deadlines were missed. In this building a bad night on the queue isn't a statistic — it's customer data walking out the door while the alert that would have caught it sits misfiled.

HR will be in touch this afternoon regarding next steps. I'm sorry — this role isn't the right fit. Please hand your badge to security on the way out.

— Marcus Webb
SOC Manager, Northbridge Financial`, 'final-fired')
  }
