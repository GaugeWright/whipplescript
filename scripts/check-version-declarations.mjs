#!/usr/bin/env node
// Every place this repository states WhippleScript's version agrees with the
// one declaration, `[workspace.package] version` in the root Cargo.toml
// (GaugeWright DR-0170 — that repository runs its own DR sequence).
//
// WhippleScript is one product with one version: every crate and package a
// release ships carries the number the workspace declares, and the cut refuses
// a tag that differs from it (scripts/release-fleet.sh). Asking only at the cut
// is too late, and the number has drifted between cuts before: the workspace
// was 0.5.6 while all 24 intra-workspace pins still said 0.5.5, which caret
// semantics hid because a `0.5.5` requirement accepts 0.5.6. So this runs on
// every change, and it reads every place a version is stated:
//
//   member crates    `[package] version` inherits the workspace's
//                    (`version.workspace = true`). A literal is refused even
//                    when it is equal, because it is a second declaration the
//                    next cut has to remember to change.
//   internal pins    a dependency on a member — in any dependency table of any
//                    manifest, `[workspace.dependencies]` included — that
//                    states a `version` names exactly that member's version.
//                    Cargo cannot inherit this field (`version = { workspace =
//                    true }` inside a dependency is "invalid type: map"), so
//                    these are copies, and this is what keeps them honest.
//   Cargo.lock       each member's entry is at the member's version. Cargo
//                    rewrites a stale one on the next build, but `--locked`,
//                    which the cut's package step uses, refuses it.
//   other manifests  a Cargo.toml that is no member (third-party/'s reindeer
//                    input) releases nothing: `0.0.0` and `publish = false`.
//   package.json     a private package is no release and has no product
//                    version: none, or `0.0.0`. A package npm would publish
//                    carries the product's. The package-lock.json beside
//                    either records the same number.
//
// Two places are generated rather than declared, and each is checked where it
// is generated: the CARGO_PKG_VERSION values in native-crates.bzl (the
// native-crates section re-renders and compares), and the installers and the
// Homebrew formula (dist writes them from Cargo.toml at the cut). A
// WhippleScript package manifest under vendored-std/ or std/ carries the
// version of that language package, which is its own identity and not the
// product's, and is not read here.
//
// THE ONE EXCEPTION is a maintenance release off a support branch (the release
// checklist, spec/release-checklist.md, "Maintenance releases off a support
// branch"): a crates.io-only fix to an older line versions only the crates it
// changes, so on that branch some members carry a literal version above the
// workspace's. That is never inferred from what the manifests happen to say.
// The branch declares it, in the root Cargo.toml:
//
//   [workspace.metadata.maintenance]
//   branch = "v0.4.x"
//   crates = { whipplescript = "0.4.2", whipplescript-store = "0.4.2" }
//
// and this check then accepts exactly those literals and nothing else. Each
// named crate must be a member that declares that version, each version must
// be a later patch of the workspace's own line, a pin on a named crate must
// name its version, and every crate not named must still inherit. Every run
// prints the exemption, so it is never silent, and a marker that reached
// `main` would stop passing at the next main-line cut, whose version is no
// longer below the marker's on the same line.
//
// Run standalone to check the tree; `--selftest` runs the parser and every
// rule over fixtures, so the checker's own logic is guarded too.

import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, posix, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// ---------------------------------------------------------------------------
// A TOML reader, enough of TOML 1.0 for Cargo manifests. By hand, because the
// bar's Node has no TOML parser and the Mac gate host's Python (Apple's 3.9)
// has no tomllib; scripts/buckify-crates.py reads by hand for the same reason.
// It refuses what it cannot read rather than guessing, so a manifest form it
// does not know is a red naming the file, never a pin it skipped.
// ---------------------------------------------------------------------------

export function parseToml(text) {
    const root = {}
    let table = root
    let pos = 0
    const len = text.length
    const fail = (message) => {
        const line = text.slice(0, pos).split('\n').length
        throw new Error(`line ${line}: ${message}`)
    }
    const peek = (s) => text.startsWith(s, pos)
    const isObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v)
    const skipSpace = () => {
        while (pos < len && (text[pos] === ' ' || text[pos] === '\t')) pos += 1
    }
    const skipComment = () => {
        if (text[pos] === '#') while (pos < len && text[pos] !== '\n') pos += 1
    }
    const skipBlank = () => {
        for (;;) {
            skipSpace()
            skipComment()
            if (text[pos] === '\n' || text[pos] === '\r') {
                pos += 1
                continue
            }
            return
        }
    }
    const endOfLine = () => {
        skipSpace()
        skipComment()
        if (pos >= len) return
        if (text[pos] === '\r') pos += 1
        if (text[pos] !== '\n') fail('expected the end of the line')
        pos += 1
    }
    const escape = () => {
        const c = text[pos + 1]
        const simple = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' }
        if (Object.hasOwn(simple, c)) {
            pos += 2
            return simple[c]
        }
        if (c === 'u' || c === 'U') {
            const width = c === 'u' ? 4 : 8
            const hex = text.slice(pos + 2, pos + 2 + width)
            if (hex.length !== width || !/^[0-9A-Fa-f]+$/.test(hex)) fail('malformed unicode escape')
            pos += 2 + width
            return String.fromCodePoint(parseInt(hex, 16))
        }
        return fail(`unknown escape \\${c}`)
    }
    const basicString = () => {
        pos += 1
        let out = ''
        while (pos < len && text[pos] !== '"') {
            if (text[pos] === '\n') fail('newline inside a string')
            if (text[pos] === '\\') out += escape()
            else out += text[pos++]
        }
        if (pos >= len) fail('unterminated string')
        pos += 1
        return out
    }
    const literalString = () => {
        const end = text.indexOf("'", pos + 1)
        const newline = text.indexOf('\n', pos + 1)
        if (end < 0 || (newline >= 0 && newline < end)) fail('unterminated literal string')
        const out = text.slice(pos + 1, end)
        pos = end + 1
        return out
    }
    const multiline = (delimiter, escapes) => {
        pos += 3
        if (text[pos] === '\r') pos += 1
        if (text[pos] === '\n') pos += 1
        let out = ''
        while (pos < len && !peek(delimiter)) {
            if (escapes && text[pos] === '\\') {
                let j = pos + 1
                while (text[j] === ' ' || text[j] === '\t') j += 1
                if (text[j] === '\n' || text[j] === '\r') {
                    pos = j
                    while (pos < len && /\s/.test(text[pos])) pos += 1
                    continue
                }
                out += escape()
                continue
            }
            out += text[pos++]
        }
        if (pos >= len) fail('unterminated multi-line string')
        pos += 3
        // A delimiter run of four or five closes the string after one or two
        // quotes that belong to it.
        for (let extra = 0; extra < 2 && text[pos] === delimiter[0]; extra += 1) out += text[pos++]
        return out
    }
    const simpleKey = () => {
        if (text[pos] === '"') return basicString()
        if (text[pos] === "'") return literalString()
        const start = pos
        while (pos < len && /[A-Za-z0-9_-]/.test(text[pos])) pos += 1
        if (pos === start) fail('expected a key')
        return text.slice(start, pos)
    }
    const dottedKey = () => {
        const parts = [simpleKey()]
        for (;;) {
            skipSpace()
            if (text[pos] !== '.') return parts
            pos += 1
            skipSpace()
            parts.push(simpleKey())
        }
    }
    const assign = (target, parts, value) => {
        let t = target
        for (const part of parts.slice(0, -1)) {
            if (!Object.hasOwn(t, part)) t[part] = {}
            t = t[part]
            if (!isObject(t)) fail(`${parts.join('.')} extends a value that is not a table`)
        }
        const last = parts[parts.length - 1]
        if (Object.hasOwn(t, last)) fail(`${parts.join('.')} is defined twice`)
        t[last] = value
    }
    const value = () => {
        if (peek('"""')) return multiline('"""', true)
        if (peek("'''")) return multiline("'''", false)
        if (text[pos] === '"') return basicString()
        if (text[pos] === "'") return literalString()
        if (text[pos] === '[') {
            pos += 1
            const out = []
            for (;;) {
                skipBlank()
                if (text[pos] === ']') {
                    pos += 1
                    return out
                }
                out.push(value())
                skipBlank()
                if (text[pos] === ',') pos += 1
                else if (text[pos] !== ']') fail('expected , or ] in an array')
            }
        }
        if (text[pos] === '{') {
            pos += 1
            const out = {}
            skipSpace()
            if (text[pos] === '}') {
                pos += 1
                return out
            }
            for (;;) {
                skipSpace()
                const parts = dottedKey()
                if (text[pos] !== '=') fail('expected = in an inline table')
                pos += 1
                skipSpace()
                assign(out, parts, value())
                skipSpace()
                if (text[pos] === '}') {
                    pos += 1
                    return out
                }
                if (text[pos] !== ',') fail('expected , or } in an inline table')
                pos += 1
            }
        }
        const start = pos
        while (pos < len && /[A-Za-z0-9_+\-.:]/.test(text[pos])) pos += 1
        const raw = text.slice(start, pos)
        if (!raw) fail('expected a value')
        if (raw === 'true') return true
        if (raw === 'false') return false
        const number = Number(raw.replace(/_/g, ''))
        return Number.isNaN(number) ? raw : number
    }
    const header = () => {
        const arrayOf = peek('[[')
        pos += arrayOf ? 2 : 1
        skipSpace()
        const parts = dottedKey()
        if (!peek(arrayOf ? ']]' : ']')) fail('unterminated table header')
        pos += arrayOf ? 2 : 1
        let t = root
        for (const part of parts.slice(0, -1)) {
            if (!Object.hasOwn(t, part)) t[part] = {}
            t = t[part]
            if (Array.isArray(t)) t = t[t.length - 1]
            if (!isObject(t)) fail(`[${parts.join('.')}] extends a value that is not a table`)
        }
        const last = parts[parts.length - 1]
        if (arrayOf) {
            if (!Object.hasOwn(t, last)) t[last] = []
            if (!Array.isArray(t[last])) fail(`[[${parts.join('.')}]] is already a table`)
            const fresh = {}
            t[last].push(fresh)
            return fresh
        }
        if (!Object.hasOwn(t, last)) t[last] = {}
        if (!isObject(t[last])) fail(`[${parts.join('.')}] is already a value`)
        return t[last]
    }

    for (;;) {
        skipBlank()
        if (pos >= len) return root
        if (text[pos] === '[') {
            table = header()
        } else {
            const parts = dottedKey()
            if (text[pos] !== '=') fail('expected =')
            pos += 1
            skipSpace()
            assign(table, parts, value())
        }
        endOfLine()
    }
}

// ---------------------------------------------------------------------------
// The rules.
// ---------------------------------------------------------------------------

const VERSION = /^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$/
const DEPENDENCY_TABLES = ['dependencies', 'dev-dependencies', 'build-dependencies', 'dev_dependencies', 'build_dependencies']
// A requirement that names one version: `0.7.0`, `^0.7.0`, or `=0.7.0`.
const EXACT_REQUIREMENT = /^\s*[\^=]?\s*(\S+)\s*$/

const isTable = (v) => typeof v === 'object' && v !== null && !Array.isArray(v)
const baseName = (p) => p.slice(p.lastIndexOf('/') + 1)
const dirOf = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '.')
const normal = (p) => {
    const n = posix.normalize(p).replace(/\/+$/, '')
    return n === '' ? '.' : n
}
const globToRegExp = (pattern) =>
    new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`)

function* dependencyEntries(manifest) {
    for (const t of DEPENDENCY_TABLES) {
        if (isTable(manifest[t])) for (const e of Object.entries(manifest[t])) yield [`[${t}]`, ...e]
    }
    if (isTable(manifest.target)) {
        for (const [cfg, body] of Object.entries(manifest.target)) {
            if (!isTable(body)) continue
            for (const t of DEPENDENCY_TABLES) {
                if (isTable(body[t])) for (const e of Object.entries(body[t])) yield [`[target.'${cfg}'.${t}]`, ...e]
            }
        }
    }
    if (isTable(manifest.workspace) && isTable(manifest.workspace.dependencies)) {
        for (const e of Object.entries(manifest.workspace.dependencies)) yield ['[workspace.dependencies]', ...e]
    }
}

/// Check every version declaration in `files`, a Map of repository-relative
/// path to contents. Returns what disagrees, what is exempt, and what was read.
export function checkVersions(files) {
    const findings = []
    const notes = []
    const counts = { inherited: 0, pins: 0, locked: 0, others: 0, packages: 0 }
    const result = () => ({ findings, notes, counts, declared })
    const cache = new Map()
    const toml = (path) => {
        if (!cache.has(path)) {
            try {
                cache.set(path, parseToml(files.get(path)))
            } catch (error) {
                findings.push(`${path}: cannot be read as TOML (${error.message})`)
                cache.set(path, null)
            }
        }
        return cache.get(path)
    }

    let declared
    if (!files.has('Cargo.toml')) {
        findings.push('Cargo.toml: absent, so there is no [workspace.package] version to agree with')
        return result()
    }
    const root = toml('Cargo.toml')
    if (!root) return result()
    const workspace = isTable(root.workspace) ? root.workspace : {}
    declared = isTable(workspace.package) ? workspace.package.version : undefined
    if (typeof declared !== 'string') {
        findings.push('Cargo.toml: [workspace.package] declares no version, and it is the one declaration every other agrees with')
        return result()
    }
    const line = VERSION.exec(declared)
    if (!line) {
        findings.push(`Cargo.toml: [workspace.package] version "${declared}" is not MAJOR.MINOR.PATCH`)
        return result()
    }

    // The members, by directory and by package name.
    const cargoPaths = [...files.keys()].filter((p) => baseName(p) === 'Cargo.toml').sort()
    const cargoDirs = new Set(cargoPaths.map(dirOf))
    const excluded = (Array.isArray(workspace.exclude) ? workspace.exclude : []).map(normal)
    const memberDirs = new Set()
    if (isTable(root.package)) memberDirs.add('.')
    for (const pattern of Array.isArray(workspace.members) ? workspace.members : []) {
        const p = normal(String(pattern))
        if (/[*?]/.test(p)) {
            const re = globToRegExp(p)
            for (const d of cargoDirs) if (re.test(d)) memberDirs.add(d)
        } else if (cargoDirs.has(p)) {
            memberDirs.add(p)
        } else {
            findings.push(`Cargo.toml: workspace member ${p} has no tracked Cargo.toml`)
        }
    }
    for (const d of excluded) memberDirs.delete(d)

    const members = new Map() // dir -> { path, name, manifest }
    for (const dir of [...memberDirs].sort()) {
        const path = dir === '.' ? 'Cargo.toml' : `${dir}/Cargo.toml`
        const manifest = toml(path)
        if (!manifest) continue
        const name = isTable(manifest.package) ? manifest.package.name : undefined
        if (typeof name !== 'string') {
            findings.push(`${path}: a workspace member with no [package] name`)
            continue
        }
        members.set(dir, { path, name, manifest })
    }
    const byName = new Map([...members.values()].map((m) => [m.name, m]))

    // The maintenance exception, only where it is declared.
    const detached = new Map() // crate name -> the version the marker gives it
    const marker = isTable(workspace.metadata) ? workspace.metadata.maintenance : undefined
    if (marker !== undefined) {
        const where = 'Cargo.toml [workspace.metadata.maintenance]'
        if (!isTable(marker)) {
            findings.push(`${where}: must be a table naming a branch and its crates`)
        } else {
            if (typeof marker.branch !== 'string' || marker.branch === '') {
                findings.push(`${where}: names no support branch; a maintenance release is cut on one`)
            }
            const crates = isTable(marker.crates) ? Object.entries(marker.crates) : []
            if (crates.length === 0) findings.push(`${where}: names no crates, so it exempts nothing; remove it`)
            for (const [name, version] of crates) {
                const v = typeof version === 'string' ? VERSION.exec(version) : null
                if (!byName.has(name)) {
                    findings.push(`${where}: names ${name}, which is not a workspace member`)
                } else if (!v || v[1] !== line[1] || v[2] !== line[2] || Number(v[3]) <= Number(line[3])) {
                    findings.push(
                        `${where}: ${name} = "${version}" is not a later patch of the workspace's own ` +
                            `${line[1]}.${line[2]} line (${declared}); a maintenance release fixes an older line without breaking it`,
                    )
                } else {
                    detached.set(name, version)
                    notes.push(
                        `maintenance release off ${marker.branch}: ${name} is ${version} while the workspace is ${declared} (${where})`,
                    )
                }
            }
        }
    }
    const versionOf = (member) => detached.get(member.name) ?? declared

    // Each member inherits, or carries exactly its declared exemption.
    for (const member of members.values()) {
        const v = member.manifest.package.version
        const inherits = isTable(v) && v.workspace === true && Object.keys(v).length === 1
        const exempt = detached.get(member.name)
        if (exempt !== undefined) {
            if (inherits) {
                findings.push(
                    `${member.path}: the maintenance marker gives ${member.name} ${exempt}, but it inherits the workspace's ` +
                        `version; detach it (version = "${exempt}") or take it out of the marker`,
                )
            } else if (v !== exempt) {
                findings.push(`${member.path}: [package] version is ${JSON.stringify(v)}, but the maintenance marker gives it ${exempt}`)
            }
        } else if (inherits) {
            counts.inherited += 1
        } else if (typeof v === 'string') {
            findings.push(
                `${member.path}: [package] version = "${v}" is a second declaration` +
                    (v === declared ? '' : ` and disagrees with ${declared}`) +
                    '; inherit the workspace version with `version.workspace = true`',
            )
        } else if (v === undefined) {
            findings.push(`${member.path}: [package] declares no version, which cargo reads as 0.0.0; inherit it with \`version.workspace = true\``)
        } else {
            findings.push(`${member.path}: [package] version is ${JSON.stringify(v)}; inherit it with \`version.workspace = true\``)
        }
    }

    // Every pin on a member names that member's version.
    const manifests = [...members.values()].map((m) => [m.path, m.manifest])
    if (!memberDirs.has('.')) manifests.unshift(['Cargo.toml', root])
    for (const [path, manifest] of manifests) {
        const dir = dirOf(path)
        for (const [table, key, raw] of dependencyEntries(manifest)) {
            const spec = typeof raw === 'string' ? { version: raw } : raw
            if (!isTable(spec) || spec.workspace === true) continue
            let target
            if (typeof spec.path === 'string') {
                target = members.get(normal(posix.join(dir, spec.path)))
            } else if (spec.git === undefined) {
                target = byName.get(typeof spec.package === 'string' ? spec.package : key)
            }
            if (!target || spec.version === undefined) continue
            counts.pins += 1
            const expected = versionOf(target)
            const named = typeof spec.version === 'string' ? EXACT_REQUIREMENT.exec(spec.version) : null
            if (!named || named[1] !== expected) {
                findings.push(
                    `${path} ${table} ${key}: version = ${JSON.stringify(spec.version)}, but ${target.name} is ${expected}; ` +
                        `set it to "${expected}" — cargo cannot inherit this field`,
                )
            }
        }
    }

    // The lockfile's entry for each member.
    const lock = files.get('Cargo.lock')
    if (lock !== undefined) {
        for (const block of lock.split(/^\[\[package\]\]\s*$/m).slice(1)) {
            const name = /^name = "([^"]*)"/m.exec(block)?.[1]
            const version = /^version = "([^"]*)"/m.exec(block)?.[1]
            if (!byName.has(name) || /^source = /m.test(block)) continue
            counts.locked += 1
            const expected = versionOf(byName.get(name))
            if (version !== expected) {
                findings.push(`Cargo.lock: records ${name} ${version}, but it is ${expected}; any cargo command without --locked rewrites it`)
            }
        }
    }

    // A Cargo manifest that is no member releases nothing.
    const memberPaths = new Set([...members.values()].map((m) => m.path))
    for (const path of cargoPaths) {
        if (path === 'Cargo.toml' || memberPaths.has(path)) continue
        const manifest = toml(path)
        if (!manifest || !isTable(manifest.package)) continue
        counts.others += 1
        const { version, publish } = manifest.package
        const unpublished = publish === false || (Array.isArray(publish) && publish.length === 0)
        if (version !== '0.0.0' || !unpublished) {
            findings.push(
                `${path}: not a workspace member, so it is no release and carries no product version; ` +
                    `declare version = "0.0.0" and publish = false (it has ${JSON.stringify(version)} and publish = ${JSON.stringify(publish)})`,
            )
        }
    }

    // npm packages, and the lockfile beside each.
    for (const path of [...files.keys()].filter((p) => baseName(p) === 'package.json').sort()) {
        if (path.split('/').includes('node_modules')) continue
        let pkg
        try {
            pkg = JSON.parse(files.get(path))
        } catch (error) {
            findings.push(`${path}: cannot be read as JSON (${error.message})`)
            continue
        }
        counts.packages += 1
        if (pkg.private === true) {
            if (pkg.version !== undefined && pkg.version !== '0.0.0') {
                findings.push(
                    `${path}: a private package is no release and has no product version; ` +
                        `set "version" to "0.0.0" or remove it (it has ${JSON.stringify(pkg.version)})`,
                )
            }
        } else if (pkg.version !== declared) {
            findings.push(
                `${path}: not private, so npm would publish it and it carries the product version ${declared} ` +
                    `(it has ${JSON.stringify(pkg.version)}); or mark it "private": true`,
            )
        }
        const lockPath = dirOf(path) === '.' ? 'package-lock.json' : `${dirOf(path)}/package-lock.json`
        if (!files.has(lockPath)) continue
        let lockfile
        try {
            lockfile = JSON.parse(files.get(lockPath))
        } catch (error) {
            findings.push(`${lockPath}: cannot be read as JSON (${error.message})`)
            continue
        }
        const recorded = [['version', lockfile.version]]
        if (isTable(lockfile.packages) && isTable(lockfile.packages[''])) recorded.push(['packages[""].version', lockfile.packages[''].version])
        for (const [field, v] of recorded) {
            if (v !== pkg.version) {
                findings.push(`${lockPath}: ${field} is ${JSON.stringify(v)}, but ${path} declares ${JSON.stringify(pkg.version)}`)
            }
        }
    }

    return result()
}

// ---------------------------------------------------------------------------
// The tree.
// ---------------------------------------------------------------------------

const READ = new Set(['Cargo.toml', 'package.json', 'package-lock.json'])

function listFiles(root) {
    // Tracked files only, deliberately: an untracked listing would reach every
    // node_modules/ and build output that a .gitignore excludes, and under the
    // read sandbox an undeclared .gitignore is no file at all.
    try {
        return execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8', maxBuffer: 256 << 20 })
            .split('\0')
            .filter(Boolean)
    } catch {
        // Not a git checkout: walk the tree, skipping what git would ignore.
        const out = []
        const walk = (dir) => {
            for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
                if (entry.name.startsWith('.') || ['node_modules', 'target', 'buck-out'].includes(entry.name)) continue
                const rel = dir ? `${dir}/${entry.name}` : entry.name
                if (entry.isDirectory()) walk(rel)
                else out.push(rel)
            }
        }
        walk('')
        return out
    }
}

function readTree(root) {
    const files = new Map()
    for (const path of listFiles(root)) {
        const wanted = READ.has(baseName(path)) || path === 'Cargo.lock'
        if (wanted && existsSync(join(root, path))) files.set(path, readFileSync(join(root, path), 'utf8'))
    }
    return files
}

// ---------------------------------------------------------------------------
// The checker's own tests.
// ---------------------------------------------------------------------------

function selftest() {
    const cases = []
    const check = (name, actual, expected) => {
        const ok = JSON.stringify(actual) === JSON.stringify(expected)
        cases.push({ name, ok, actual, expected })
    }
    const fails = (name, fn) => {
        let threw = false
        try {
            fn()
        } catch {
            threw = true
        }
        cases.push({ name, ok: threw, actual: threw ? 'threw' : 'accepted', expected: 'threw' })
    }

    // The reader.
    const parsed = parseToml(
        [
            '# a comment',
            '[package]',
            'name = "a"  # trailing',
            'version.workspace = true',
            'description = "has a # and \\"quotes\\" \\u00e9"',
            "literal = 'C:\\path'",
            'multi = """',
            'one \\',
            '   two"""',
            'list = [',
            '    "x", # between',
            '    "y",',
            ']',
            '',
            "[target.'cfg(target_arch = \"wasm32\")'.dependencies]",
            'b = { version = "1.0.0", path = "../b", features = ["f"] }',
            '',
            '[dependencies.c]',
            'version = "2.0.0"',
            '',
            '[[bin]]',
            'name = "one"',
            '[[bin]]',
            'name = "two"',
            'n = 1_000',
            'on = true',
        ].join('\n'),
    )
    check('dotted key', parsed.package.version, { workspace: true })
    check('escapes and a # inside a string', parsed.package.description, 'has a # and "quotes" é')
    check('literal string keeps backslashes', parsed.package.literal, 'C:\\path')
    check('multi-line string trims a line-ending backslash', parsed.package.multi, 'one two')
    check('multi-line array with comments', parsed.package.list, ['x', 'y'])
    check('quoted cfg key and inline table', parsed.target['cfg(target_arch = "wasm32")'].dependencies.b, {
        version: '1.0.0',
        path: '../b',
        features: ['f'],
    })
    check('sub-table form', parsed.dependencies.c, { version: '2.0.0' })
    check('array of tables', parsed.bin.map((b) => b.name), ['one', 'two'])
    check('numbers and booleans', [parsed.bin[1].n, parsed.bin[1].on], [1000, true])
    fails('a key defined twice is refused', () => parseToml('a = 1\na = 2'))
    fails('an unterminated string is refused', () => parseToml('a = "x\n'))
    fails('trailing junk is refused', () => parseToml('a = 1 b'))
    fails('an unterminated header is refused', () => parseToml('[a\n'))

    // A tree that agrees.
    const ws = (extra = '') =>
        [
            '[workspace]',
            'members = ["crates/*"]',
            'exclude = ["vendor"]',
            '[workspace.package]',
            'version = "0.7.0"',
            extra,
        ].join('\n')
    const crate = (name, deps = '', version = 'version.workspace = true') =>
        `[package]\nname = "${name}"\n${version}\n${deps}\n`
    const lockEntry = (name, version, source = '') =>
        `[[package]]\nname = "${name}"\nversion = "${version}"\n${source}\n`
    const tree = (overrides = {}) =>
        new Map(
            Object.entries({
                'Cargo.toml': ws(),
                'crates/core/Cargo.toml': crate('core'),
                'crates/cli/Cargo.toml': crate(
                    'cli',
                    [
                        '[dependencies]',
                        'core = { version = "0.7.0", path = "../core" }',
                        'serde = "1.0.0"',
                        "[target.'cfg(unix)'.dev-dependencies]",
                        'core = { version = "^0.7.0", path = "../core", features = ["x"] }',
                    ].join('\n'),
                ),
                'Cargo.lock': 'version = 4\n\n' + lockEntry('cli', '0.7.0') + lockEntry('core', '0.7.0') +
                    lockEntry('serde', '1.0.0', 'source = "registry+https://github.com/rust-lang/crates.io-index"'),
                'vendor/Cargo.toml': '[package]\nname = "tp"\nversion = "0.0.0"\npublish = false\n',
                'package.json': '{ "private": true }',
                'worker/package.json': '{ "name": "w", "private": true, "version": "0.0.0" }',
                'worker/package-lock.json': '{ "name": "w", "version": "0.0.0", "packages": { "": { "version": "0.0.0" } } }',
                ...overrides,
            }).filter(([, v]) => v !== null),
        )
    const findings = (overrides) => checkVersions(tree(overrides)).findings
    const clean = checkVersions(tree())
    check('a tree that agrees has no findings', clean.findings, [])
    check('and says what it read', clean.counts, { inherited: 2, pins: 2, locked: 2, others: 1, packages: 2 })

    check('an exact requirement is accepted', findings({
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\ncore = { version = "=0.7.0", path = "../core" }'),
    }), [])
    check('a drifted pin is a finding', findings({
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\ncore = { version = "0.6.0", path = "../core" }'),
    }).length, 1)
    check('a drifted pin in a target table is a finding', findings({
        'crates/cli/Cargo.toml': crate('cli', "[target.'cfg(unix)'.build-dependencies]\ncore = { version = \"0.7.1\", path = \"../core\" }"),
    }).length, 1)
    check('a drifted pin in sub-table form is a finding', findings({
        'crates/cli/Cargo.toml': crate('cli', '[dev-dependencies.core]\nversion = "0.6.0"\npath = "../core"'),
    }).length, 1)
    check('a renamed dependency is followed to its package', findings({
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\nkernel = { package = "core", version = "0.6.0" }'),
    }).length, 1)
    check('a registry requirement on a member is a pin too', findings({
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\ncore = "0.6.0"'),
    }).length, 1)
    check('a range is not a pin that names the version', findings({
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\ncore = { version = ">=0.6, <0.8", path = "../core" }'),
    }).length, 1)
    check('a pin in [workspace.dependencies] is checked', findings({
        'Cargo.toml': ws('[workspace.dependencies]\ncore = { version = "0.6.0", path = "crates/core" }'),
    }).length, 1)
    check('a dependency on a non-member is not a pin', findings({
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\ntp = { version = "9.9.9", path = "../../vendor" }'),
    }), [])
    check('an equal literal member version is a second declaration', findings({
        'crates/core/Cargo.toml': crate('core', '', 'version = "0.7.0"'),
    }).length, 1)
    check('a member with no version is a finding', findings({
        'crates/core/Cargo.toml': crate('core', '', ''),
    }).length, 1)
    check('a stale lockfile entry is a finding', findings({
        'Cargo.lock': lockEntry('cli', '0.6.0') + lockEntry('core', '0.7.0'),
    }).length, 1)
    check('a registry package that shares a name is not a member entry', findings({
        'Cargo.lock': lockEntry('cli', '0.7.0') + lockEntry('core', '0.7.0') +
            lockEntry('core', '0.1.0', 'source = "registry+https://github.com/rust-lang/crates.io-index"'),
    }), [])
    check('a non-member manifest with a version is a finding', findings({
        'vendor/Cargo.toml': '[package]\nname = "tp"\nversion = "0.1.0"\npublish = false\n',
    }).length, 1)
    check('a non-member manifest that could publish is a finding', findings({
        'vendor/Cargo.toml': '[package]\nname = "tp"\nversion = "0.0.0"\n',
    }).length, 1)
    check('a private package with a version is a finding', findings({
        'worker/package.json': '{ "private": true, "version": "0.1.0" }',
        'worker/package-lock.json': '{ "version": "0.1.0", "packages": { "": { "version": "0.1.0" } } }',
    }).length, 1)
    check('a publishable package carries the product version', findings({
        'worker/package.json': '{ "version": "0.7.0" }',
        'worker/package-lock.json': '{ "version": "0.7.0", "packages": { "": { "version": "0.7.0" } } }',
    }), [])
    check('a publishable package at another version is a finding', findings({
        'worker/package.json': '{ "version": "0.0.0" }',
    }).length, 1)
    check('a lockfile that disagrees with its package is a finding', findings({
        'worker/package-lock.json': '{ "version": "0.1.0", "packages": { "": { "version": "0.1.0" } } }',
    }).length, 2)
    check('node_modules is not read', findings({
        'worker/node_modules/x/package.json': '{ "version": "3.0.0" }',
    }), [])
    check('a malformed workspace version is a finding', findings({
        'Cargo.toml': ws().replace('"0.7.0"', '"0.7"'),
    }).length, 1)
    check('an unreadable manifest is a finding that names it', findings({
        'crates/core/Cargo.toml': '[package\n',
    }).some((f) => f.startsWith('crates/core/Cargo.toml: cannot be read')), true)

    // The maintenance exception.
    const maintenance = (crates) => ws(`[workspace.metadata.maintenance]\nbranch = "v0.7.x"\ncrates = ${crates}`)
    const detachedTree = {
        'Cargo.toml': maintenance('{ core = "0.7.1" }'),
        'crates/core/Cargo.toml': crate('core', '', 'version = "0.7.1"'),
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\ncore = { version = "0.7.1", path = "../core" }'),
        'Cargo.lock': lockEntry('cli', '0.7.0') + lockEntry('core', '0.7.1'),
    }
    const exempt = checkVersions(tree(detachedTree))
    check('a declared maintenance release passes', exempt.findings, [])
    check('and says so on every run', exempt.notes.length, 1)
    check('a detached crate the marker does not name is a finding', findings({
        ...detachedTree,
        'Cargo.toml': maintenance('{ cli = "0.7.1" }'),
    }).some((f) => f.includes('crates/core/Cargo.toml: [package] version = "0.7.1"')), true)
    check('the marker naming a crate that inherits is a finding', findings({
        'Cargo.toml': maintenance('{ core = "0.7.1" }'),
    }).some((f) => f.includes('but it inherits')), true)
    check('a marker version off the workspace line is a finding', findings({
        ...detachedTree,
        'Cargo.toml': maintenance('{ core = "0.8.0" }'),
    }).some((f) => f.includes('not a later patch')), true)
    check('a marker version at or below the workspace is a finding', findings({
        ...detachedTree,
        'Cargo.toml': maintenance('{ core = "0.7.0" }'),
    }).some((f) => f.includes('not a later patch')), true)
    check('a marker naming no member is a finding', findings({
        'Cargo.toml': maintenance('{ nothing = "0.7.1" }'),
    }).length, 1)
    check('a marker with no branch is a finding', findings({
        ...detachedTree,
        'Cargo.toml': ws('[workspace.metadata.maintenance]\ncrates = { core = "0.7.1" }'),
    }).length, 1)
    check('a pin on a detached crate names its version', findings({
        ...detachedTree,
        'crates/cli/Cargo.toml': crate('cli', '[dependencies]\ncore = { version = "0.7.0", path = "../core" }'),
    }).length, 1)

    const failed = cases.filter((c) => !c.ok)
    for (const c of failed) {
        console.error(`selftest FAILED: ${c.name}`)
        console.error(`  expected ${JSON.stringify(c.expected)}`)
        console.error(`  actual   ${JSON.stringify(c.actual)}`)
    }
    if (failed.length) process.exit(1)
    console.log(`version-declarations selftest: ${cases.length} cases passed`)
}

// ---------------------------------------------------------------------------

if (process.argv.includes('--selftest')) {
    selftest()
    process.exit(0)
}

const rootArg = process.argv.find((a) => a.startsWith('--root='))
const root = rootArg ? resolve(rootArg.slice('--root='.length)) : resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { findings, notes, counts, declared } = checkVersions(readTree(root))
for (const note of notes) console.log(note)
if (findings.length) {
    console.error(
        `error: a version declaration disagrees with [workspace.package] version${declared ? ` ${declared}` : ''} ` +
            'in Cargo.toml.\nThe product has one version, declared there once; everything else inherits it, is ' +
            'generated from it,\nor is a copy this check holds to it (GaugeWright DR-0170).\n',
    )
    for (const f of findings) console.error(`  ${f}`)
    process.exit(1)
}
console.log(
    `version declarations: ${counts.inherited} crates inherit ${declared}, ${counts.pins} internal pins and ` +
        `${counts.locked} Cargo.lock entries name their crate's version, ${counts.others} other Cargo manifests ` +
        `and ${counts.packages} package.json files release nothing or carry it`,
)
