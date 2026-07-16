// Randomization helpers used by the alert generator to make every run unique.

export function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

export function pickN(arr, n) {
  const copy = [...arr]
  const out = []
  while (out.length < n && copy.length > 0) {
    out.push(copy.splice(Math.floor(Math.random() * copy.length), 1)[0])
  }
  return out
}

export function shuffle(arr) {
  const copy = [...arr]
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[copy[i], copy[j]] = [copy[j], copy[i]]
  }
  return copy
}

export function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

const FIRST_NAMES = ['james', 'anna', 'piotr', 'maria', 'tomas', 'kate', 'lukas', 'nina', 'marek', 'julia', 'adam', 'ewa', 'oliver', 'zofia', 'daniel', 'laura', 'victor', 'iris', 'pawel', 'clara']
const LAST_NAMES = ['kowalski', 'smith', 'nowak', 'jones', 'wisniewski', 'brown', 'mazur', 'taylor', 'krawczyk', 'walker', 'zielinski', 'moore', 'kaminski', 'hughes', 'lewicki', 'grant']

export function randomUser() {
  return `${pick(FIRST_NAMES)[0]}${pick(LAST_NAMES)}`
}

export function randomFullNameAndUser() {
  const f = pick(FIRST_NAMES)
  const l = pick(LAST_NAMES)
  const cap = (s) => s[0].toUpperCase() + s.slice(1)
  return { name: `${cap(f)} ${cap(l)}`, user: `${f[0]}${l}` }
}

export function randomInternalIP() {
  return `10.${randInt(10, 40)}.${randInt(1, 254)}.${randInt(2, 254)}`
}

export function randomExternalIP() {
  // Avoid private/reserved-looking first octets for realism
  const firstOctets = [23, 45, 62, 77, 89, 91, 103, 121, 134, 146, 155, 167, 173, 185, 193, 198, 203, 212]
  return `${pick(firstOctets)}.${randInt(1, 254)}.${randInt(1, 254)}.${randInt(2, 254)}`
}

export function randomWorkstation() {
  return `WS-${pick(['FIN', 'HR', 'MKT', 'ENG', 'OPS', 'LGL'])}-${String(randInt(1, 99)).padStart(3, '0')}`
}

export function randomServer(role) {
  const r = role || pick(['APP', 'DB', 'FS', 'WEB', 'DC'])
  return `SRV-${r}-${String(randInt(1, 9)).padStart(2, '0')}`
}

// Timestamps: alerts happen "tonight" during the 22:00-06:00 shift.
export function randomShiftTime() {
  const h = pick([22, 23, 0, 1, 2, 3])
  const m = randInt(0, 59)
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`
}

// Sequence of timestamps a few seconds/minutes apart starting at a base time
export function timeSequence(count, stepSecondsMin, stepSecondsMax) {
  const h = pick([22, 23, 0, 1, 2, 3])
  let t = h * 3600 + randInt(0, 50) * 60
  const out = []
  for (let i = 0; i < count; i++) {
    const hh = Math.floor(t / 3600) % 24
    const mm = Math.floor((t % 3600) / 60)
    const ss = t % 60
    out.push(`${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}:${String(ss).padStart(2, '0')}`)
    t += randInt(stepSecondsMin, stepSecondsMax)
  }
  return out
}

let alertCounter = randInt(4000, 7000)
export function nextAlertNumber() {
  alertCounter += randInt(1, 6)
  return alertCounter
}
