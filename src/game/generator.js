import { TEMPLATES, RUN_PLAN, SLA_BY_TIER } from '../data/templates.js'
import { pickN, shuffle, nextAlertNumber, randomShiftTime } from './random.js'

// Builds one full randomized run: tiers in ascending order (shift gets harder),
// alerts shuffled within each tier so no two runs follow the same path.
export function generateRun() {
  const run = []
  for (const plan of RUN_PLAN) {
    const tpPool = TEMPLATES.filter((t) => t.tier === plan.tier && t.verdict === 'tp')
    const fpPool = TEMPLATES.filter((t) => t.tier === plan.tier && t.verdict === 'fp')
    const chosen = shuffle([...pickN(tpPool, plan.tp), ...pickN(fpPool, plan.fp)])
    for (const tpl of chosen) {
      const built = tpl.build()
      run.push({
        uid: `${tpl.id}-${Math.random().toString(36).slice(2, 8)}`,
        templateId: tpl.id,
        number: `ALT-${nextAlertNumber()}`,
        tier: tpl.tier,
        verdict: tpl.verdict,
        category: tpl.category,
        correctAction: tpl.correctAction,
        severity: tpl.severity,
        source: tpl.source,
        ruleName: tpl.ruleName,
        slaSeconds: SLA_BY_TIER[tpl.tier],
        firedAt: randomShiftTime(),
        ...built,
        status: 'new', // new -> open -> resolved
        openedAt: null,
      })
    }
  }
  return run
}
