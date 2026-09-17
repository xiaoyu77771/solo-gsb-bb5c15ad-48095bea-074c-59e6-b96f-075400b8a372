/** 审计引擎自检：node --test 风格的轻量断言脚本（零额外依赖） */
import assert from 'node:assert'
import { audit, parseRulesJson, validateRules } from './audit/engine'
import { movedRules, previewReorder } from './audit/reorder'
import type { RuleInput } from './audit/types'
import { ipv4ToInt, parseCidrStrict } from './audit/iputil'

let passed = 0
function test(name: string, fn: () => void) {
  fn()
  passed++
  console.log(`  ✓ ${name}`)
}

let seq = 0
function rule(partial: Partial<RuleInput>): RuleInput {
  return {
    id: `r${seq++}`,
    name: partial.name ?? `R${seq}`,
    cidr: partial.cidr ?? '0.0.0.0/0',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
    enabled: partial.enabled ?? true,
  }
}

// --- CIDR 严格校验 ---
test('严格 CIDR：主机位非零被拒绝', () => {
  assert.throws(() => parseCidrStrict('10.0.0.1/24'), /主机位非零/)
})

test('严格 CIDR：/32 单地址合法', () => {
  assert.doesNotThrow(() => parseCidrStrict('192.168.1.1/32'))
})

test('严格 CIDR：前缀越界 / 格式错误', () => {
  assert.throws(() => parseCidrStrict('10.0.0.0/33'))
  assert.throws(() => parseCidrStrict('10.0.0/8'))
  assert.throws(() => parseCidrStrict('999.0.0.0/8'))
  assert.throws(() => parseCidrStrict('::1/128'))
})

// --- 基础遮蔽 ---
test('相同区域的第二条规则被完全遮蔽', () => {
  const report = audit([
    rule({ name: 'A', cidr: '10.0.0.0/8' }),
    rule({ name: 'B', cidr: '10.0.0.0/8' }),
  ])
  const [a, b] = report.entries
  assert.equal(a.kind, 'valid')
  assert.equal(b.kind, 'valid')
  if (a.kind !== 'valid' || b.kind !== 'valid') return
  assert.equal(a.status, 'reachable')
  assert.equal(b.status, 'fully-shadowed')
  assert.equal(a.effectiveSize, a.declaredSize)
  assert.equal(b.effectiveSize, 0)
  assert.equal(b.shadowSources[0].ruleName, 'A')
  assert.equal(b.shadowedExamples[0].matchedRuleName, 'A')
  assert.equal(b.shadowedExamples[0].kind, 'shadowed')
  assert.equal(b.collectiveCover, false)
})

test('子集规则被完全遮蔽，外层规则部分可达', () => {
  const report = audit([
    rule({ name: 'BIG', cidr: '10.0.0.0/8', protocol: 'TCP' }),
    rule({ name: 'SMALL', cidr: '10.1.0.0/16', protocol: 'TCP' }),
  ])
  const [big, small] = report.entries
  if (big.kind !== 'valid' || small.kind !== 'valid') throw new Error('bad kinds')
  assert.equal(small.status, 'fully-shadowed')
  // BIG 在前，所有 10/8 TCP 都命中 BIG，因此 BIG 完整可达
  assert.equal(big.status, 'reachable')
  assert.equal(big.effectiveSize, big.declaredSize)
  assert.equal(small.effectiveSize, 0)
})

test('部分遮蔽：两个 /25 遮蔽一个 /24 的一半', () => {
  const report = audit([
    rule({ name: 'lo1', cidr: '10.0.0.0/25' }),
    rule({ name: 'lo2', cidr: '10.0.0.128/25' }),
    rule({ name: 'cover', cidr: '10.0.0.0/24' }),
  ])
  const cover = report.entries[2]
  if (cover.kind !== 'valid') throw new Error('bad')
  assert.equal(cover.status, 'fully-shadowed')
  assert.equal(cover.collectiveCover, true)
  // 两个来源，各自贡献一半单元
  const sources = cover.shadowSources
  assert.equal(sources.length, 2)
  assert.deepEqual(
    sources.map((s) => s.ruleName).sort(),
    ['lo1', 'lo2'],
  )
  // 两条遮蔽样例分别指向两个来源
  const matched = cover.shadowedExamples.map((e) => e.matchedRuleName).sort()
  assert.deepEqual(matched, ['lo1', 'lo2'])
})

test('部分遮蔽：前序规则只盖住一半，后半仍可达', () => {
  const report = audit([
    rule({ name: 'half', cidr: '10.0.0.0/25' }),
    rule({ name: 'full', cidr: '10.0.0.0/24' }),
  ])
  const full = report.entries[1]
  if (full.kind !== 'valid') throw new Error('bad')
  assert.equal(full.status, 'partial-shadowed')
  // 默认 ANY=TCP+UDP，故按报文空间计比例为 128/256 × 全部端口 × 2 协议 = 1/2 空间，
  // 而按单元计（IP 两半 × 2 协议）遮蔽 2/4、有效 2/4，这里展示的是报文空间比例
  assert.equal(full.effectiveSize, 128 * 65536 * 2)
  assert.equal(full.effectiveRatio, 0.5)
  assert.ok(full.reachableExample)
  assert.equal(full.reachableExample!.srcIp, '10.0.0.129')
  assert.equal(full.shadowedExamples[0].srcIp, '10.0.0.1')
  // 有效区域只含后半个 /24
  const cidrs = full.region.flatMap((g) => g.cidrs)
  assert.ok(cidrs.includes('10.0.0.128/25'))
  assert.ok(!cidrs.some((c) => c.startsWith('10.0.0.0/')))
})

test('协议维与端口维同样参与遮蔽计算', () => {
  const report = audit([
    rule({ name: 'tcp-all', cidr: '10.0.0.0/24', protocol: 'TCP' }),
    rule({ name: 'udp-80', cidr: '10.0.0.0/24', portStart: '80', portEnd: '80', protocol: 'UDP' }),
    rule({ name: 'any-all', cidr: '10.0.0.0/24', protocol: 'ANY' }),
  ])
  const [tcp, udp80, any] = report.entries
  if (tcp.kind !== 'valid' || udp80.kind !== 'valid' || any.kind !== 'valid') throw new Error('bad')
  assert.equal(tcp.status, 'reachable')
  assert.equal(udp80.status, 'reachable')
  // any-all 只拿到 UDP 1-79,81-65535
  assert.equal(any.status, 'partial-shadowed')
  const udpRegion = any.region.find((g) => g.protocol === 'UDP')!
  assert.equal(udpRegion.portRanges.length, 2)
  assert.ok(!any.region.some((g) => g.protocol === 'TCP'))
})

test('有效区域大小 = IP × 端口 × 协议，比率正确', () => {
  const report = audit([
    rule({ name: 'p', cidr: '10.0.0.0/24', portStart: '1', portEnd: '100', protocol: 'TCP' }),
    rule({
      name: 'q',
      cidr: '10.0.0.0/24',
      portStart: '1',
      portEnd: '100',
      protocol: 'TCP',
    }),
  ])
  const [p, q] = report.entries
  if (p.kind !== 'valid' || q.kind !== 'valid') throw new Error('bad')
  assert.equal(p.declaredSize, 256 * 100)
  assert.equal(q.effectiveSize, 0)
})

// --- 非法规则 ---
test('非法 CIDR / 端口不参与分析，且保留原下标', () => {
  const report = audit([
    rule({ name: 'good', cidr: '10.0.0.0/8' }),
    rule({ name: 'bad-cidr', cidr: '10.0.0.0/99' }),
    rule({ name: 'bad-port', cidr: '10.0.0.0/8', portStart: '99999', portEnd: '5' }),
    rule({ name: 'after', cidr: '10.0.0.0/8' }),
  ])
  assert.equal(report.entries.length, 4)
  assert.equal(report.entries[1].kind, 'invalid')
  assert.equal(report.entries[2].kind, 'invalid')
  assert.equal(report.entries[3].index, 3)
  const after = report.entries[3]
  if (after.kind !== 'valid') throw new Error('bad')
  assert.equal(after.status, 'fully-shadowed') // 只被 good 遮蔽，非法规则不参与
  assert.equal(after.shadowSources[0].ruleName, 'good')
})

// --- 共同覆盖：非规则长方体的补集 ---
test('十字形共同覆盖：两条规则的并集盖住 L 形区域', () => {
  // A: 左半 IP 全端口; B: 右半 IP 的低端口; C: 全 IP 低端口
  const report = audit([
    rule({ name: 'A', cidr: '10.0.0.0/25', portStart: '0', portEnd: '65535' }),
    rule({ name: 'B', cidr: '10.0.0.128/25', portStart: '0', portEnd: '1024' }),
    rule({ name: 'C', cidr: '10.0.0.0/24', portStart: '0', portEnd: '1024' }),
  ])
  const c = report.entries[2]
  if (c.kind !== 'valid') throw new Error('bad')
  assert.equal(c.status, 'fully-shadowed')
  assert.equal(c.collectiveCover, true)
  const names = c.shadowSources.map((s) => s.ruleName).sort()
  assert.deepEqual(names, ['A', 'B'])
})

// --- 示例报文可复现且确实命中所述规则 ---
test('示例报文在首条命中语义下确实命中来源规则', () => {
  const rules = [
    rule({ name: 'deny-ssh', cidr: '192.168.0.0/16', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'allow-all', cidr: '0.0.0.0/0', action: 'allow' }),
  ]
  const report = audit(rules)
  const { valid: normalized } = validateRules(rules)
  const allow = report.entries[1]
  if (allow.kind !== 'valid') throw new Error('bad')
  const ex = allow.shadowedExamples[0]
  assert.equal(ex.protocol, 'TCP')
  assert.equal(ex.srcPort, 22)
  assert.equal(ex.action, 'deny')

  // 模拟首条命中：报文必须命中 ex.matchedRuleIndex 指向的规则
  const ipNum = ipv4ToInt(ex.srcIp)
  const hit = normalized.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      ex.srcPort >= r.portStart &&
      ex.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ex.protocol),
  )
  assert.ok(hit, '示例报文必须能匹配某条规则')
  assert.equal(hit!.index, ex.matchedRuleIndex)
  assert.equal(hit!.name, 'deny-ssh')

  // 可达样例同理：命中自身
  const deny = report.entries[0]
  if (deny.kind !== 'valid') throw new Error('bad')
  const ok = deny.reachableExample!
  const hit2 = normalized.find(
    (r) =>
      ipv4ToInt(ok.srcIp) >= r.ipStart &&
      ipv4ToInt(ok.srcIp) <= r.ipEnd &&
      ok.srcPort >= r.portStart &&
      ok.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ok.protocol),
  )
  assert.equal(hit2!.index, deny.index)
})

// --- JSON 导入 ---
test('JSON 导入：数组 / {rules} / 导出报告 三种形态', () => {
  const arr = parseRulesJson(
    JSON.stringify([{ cidr: '10.0.0.0/8', portStart: 1, portEnd: 1024, protocol: 'tcp', action: 'deny' }]),
  )
  assert.equal(arr.errors.length, 0)
  assert.equal(arr.rules[0].protocol, 'TCP') // 导入时归一化大小写

  const wrapped = parseRulesJson(JSON.stringify({ rules: [{ cidr: '0.0.0.0/0', action: 'x' }] }))
  assert.equal(wrapped.rules.length, 1)

  const report = audit([rule({ name: 'A' }), rule({ name: 'B' })])
  const roundTrip = parseRulesJson(JSON.stringify(report))
  assert.equal(roundTrip.rules.length, 2)
})

test('JSON 导入：非法 JSON 报错', () => {
  const r = parseRulesJson('{not json')
  assert.ok(r.errors[0].includes('JSON 解析失败'))
})

// --- 调序影响预览 ---
test('调序预览：重叠规则互换位置产生动作变化与可复现样例', () => {
  const deny = rule({ name: 'deny-ssh', cidr: '192.168.0.0/16', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' })
  const allow = rule({ name: 'allow-all', cidr: '0.0.0.0/0', action: 'allow' })
  const current = [deny, allow]
  const candidate = [allow, deny]
  const p = previewReorder(current, candidate)

  assert.equal(p.hasDifference, true)
  assert.equal(p.actionChanges.length, 1)
  const ch = p.actionChanges[0]
  assert.equal(ch.oldRuleId, deny.id)
  assert.equal(ch.newRuleId, allow.id)
  assert.equal(ch.oldAction, 'deny')
  assert.equal(ch.newAction, 'allow')
  // 样例报文落在重叠区域 SSH 上：TCP 192.168.x.x:22
  assert.equal(ch.packet.protocol, 'TCP')
  assert.equal(ch.packet.srcPort, 22)
  const ipNum = ipv4ToInt(ch.packet.srcIp)
  assert.ok(ipNum >= ipv4ToInt('192.168.0.0') && ipNum <= ipv4ToInt('192.168.255.255'))
  // 变化空间 = /16 个 IP × 1 端口 × 1 协议
  assert.equal(ch.size, 65536)

  // 用暴力首命中复现：候选顺序下该报文必须命中 allow-all（allow）
  const { valid: cand } = validateRules(candidate)
  const hitCand = cand.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      ch.packet.srcPort >= r.portStart &&
      ch.packet.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ch.packet.protocol),
  )
  assert.equal(hitCand!.id, allow.id)
  // 当前顺序下命中 deny-ssh（deny）
  const { valid: old } = validateRules(current)
  const hitOld = old.find(
    (r) =>
      ipNum >= r.ipStart &&
      ipNum <= r.ipEnd &&
      ch.packet.srcPort >= r.portStart &&
      ch.packet.srcPort <= r.portEnd &&
      (r.protocol === 'ANY' || r.protocol === ch.packet.protocol),
  )
  assert.equal(hitOld!.id, deny.id)

  // 逐规则视图：两条规则的状态 / 有效空间都翻转
  const denyView = p.rules.find((v) => v.id === deny.id)!
  assert.equal(denyView.oldStatus, 'reachable')
  assert.equal(denyView.newStatus, 'fully-shadowed')
  assert.equal(denyView.sizeDelta, -65536)
  const allowView = p.rules.find((v) => v.id === allow.id)!
  assert.equal(allowView.sizeDelta, 65536)
})

test('调序预览：不相交规则换位仅有序号变化、无实际差异', () => {
  const a = rule({ name: 'A', cidr: '10.0.0.0/8', action: 'deny' })
  const b = rule({ name: 'B', cidr: '192.168.0.0/16', action: 'allow' })
  const current = [a, b]
  const candidate = [b, a]
  const p = previewReorder(current, candidate)

  assert.equal(p.hasDifference, false)
  assert.equal(p.actionChanges.length, 0)
  assert.equal(p.sameActionChanges.length, 0)
  assert.equal(p.totalReassignedSize, 0)
  assert.equal(p.rules.length, 2)
  assert.ok(p.rules.every((v) => v.moved && !v.auditChanged))
  assert.equal(p.rules.find((v) => v.id === b.id)!.oldIndex, 1)
  assert.equal(p.rules.find((v) => v.id === b.id)!.newIndex, 0)
  // 状态与有效空间保持不变
  assert.ok(p.rules.every((v) => v.oldStatus === v.newStatus && v.sizeDelta === 0))
})

test('调序预览：动作相同的规则互换只产生 sameActionChanges', () => {
  const a = rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' })
  const b = rule({ name: 'B', cidr: '0.0.0.0/0', action: 'allow' })
  const p = previewReorder([a, b], [b, a])
  assert.equal(p.actionChanges.length, 0)
  assert.equal(p.sameActionChanges.length, 1)
  assert.equal(p.hasDifference, true)
  assert.equal(p.sameActionChanges[0].size, 2 ** 24 * 65536 * 2)
})

test('调序预览：非法规则跟随移动但继续不参与分析', () => {
  const a = rule({ name: 'good-a', cidr: '10.0.0.0/8', action: 'allow' })
  const bad = rule({ name: 'bad', cidr: '10.0.0.5/24', action: 'allow' })
  const b = rule({ name: 'good-b', cidr: '192.168.0.0/16', action: 'deny' })
  const current = [a, bad, b]
  // 把非法规则从 #2 拖到 #3：[a, b, bad]
  const candidate = movedRules(current, 1, 2)
  assert.deepEqual(candidate.map((r) => r.id), [a.id, b.id, bad.id])
  const p = previewReorder(current, candidate)

  const badView = p.rules.find((v) => v.id === bad.id)!
  assert.equal(badView.oldStatus, 'invalid')
  assert.equal(badView.newStatus, 'invalid')
  assert.equal(badView.moved, true)
  assert.equal(badView.oldIndex, 1)
  assert.equal(badView.newIndex, 2)
  assert.equal(badView.sizeDelta, 0)
  // 合法规则区域不相交：没有任何流量归属变化
  assert.equal(p.actionChanges.length, 0)
  assert.equal(p.sameActionChanges.length, 0)
})

test('调序预览：未移动的规则也会被上移到其前面的规则遮蔽（影响不限于被拖动规则）', () => {
  // a 与 c 重叠（a 区域更窄），b 与两者不相交；a/b 同动作，c 为兜底 deny
  const a = rule({ name: 'a-web', cidr: '10.0.0.0/24', action: 'allow' })
  const b = rule({ name: 'b-other', cidr: '192.168.0.0/16', action: 'allow' })
  const c = rule({ name: 'c-deny-all', cidr: '0.0.0.0/0', action: 'deny' })
  const current = [a, b, c]
  // 把 c 从 #3 拖到 a 与 b 之间：a(index 0) 位置不变，b 下移
  const candidate = movedRules(current, 2, 1)
  assert.deepEqual(candidate.map((r) => r.id), [a.id, c.id, b.id])
  const p = previewReorder(current, candidate)

  // a 未移动，但 c 现在不在其前方，状态不变；真正被影响的是下移的 b
  const aView = p.rules.find((v) => v.id === a.id)
  if (aView) {
    assert.equal(aView.moved, false)
    assert.equal(aView.auditChanged, false)
  }
  // b 下移一位，前面插入 c(deny all)：由可达变为完全遮蔽
  const bView = p.rules.find((v) => v.id === b.id)!
  assert.equal(bView.moved, true)
  assert.equal(bView.oldStatus, 'reachable')
  assert.equal(bView.newStatus, 'fully-shadowed')
  assert.ok(bView.sizeDelta < 0)
  // 流量首命中动作：allow(b) → deny(c)
  assert.ok(p.actionChanges.length >= 1)
  const acts = new Set(
    p.actionChanges.map((ch) => `${ch.oldRuleId}>${ch.newRuleId}:${ch.oldAction}>${ch.newAction}`),
  )
  assert.ok(acts.has(`${b.id}>${c.id}:allow>deny`))
  const ch = p.actionChanges.find((x) => x.oldRuleId === b.id && x.newRuleId === c.id)!
  assert.equal(ch.packet.protocol, 'TCP')
  const ipNum = ipv4ToInt(ch.packet.srcIp)
  assert.ok(ipNum >= ipv4ToInt('192.168.0.0') && ipNum <= ipv4ToInt('192.168.255.255'))
})

console.log(`\n全部 ${passed} 项测试通过 ✔`)
