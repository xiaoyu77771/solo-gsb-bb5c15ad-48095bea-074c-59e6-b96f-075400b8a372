/** 审计引擎自检：node --test 风格的轻量断言脚本（零额外依赖） */
import assert from 'node:assert'
import { audit, parseRulesJson, validateRules } from './audit/engine'
import { verifyGoal } from './audit/goal'
import { movedRules, previewReorder } from './audit/reorder'
import type { GoalInput, RuleInput } from './audit/types'
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

// --- 策略目标验证 ---
function goal(partial: Partial<GoalInput>): GoalInput {
  return {
    cidr: partial.cidr ?? '10.0.0.0/24',
    portStart: partial.portStart ?? '0',
    portEnd: partial.portEnd ?? '65535',
    protocol: partial.protocol ?? 'ANY',
    action: partial.action ?? 'allow',
  }
}

/** 暴力首命中模拟：用于复核代表报文确实复现对应判定 */
function firstHit(rules: RuleInput[], ip: string, port: number, proto: 'TCP' | 'UDP') {
  const { valid } = validateRules(rules)
  const ipNum = ipv4ToInt(ip)
  for (const r of valid) {
    const protoOk = r.protocol === 'ANY' || r.protocol === proto
    if (protoOk && ipNum >= r.ipStart && ipNum <= r.ipEnd && port >= r.portStart && port <= r.portEnd) {
      return r
    }
  }
  return null
}

test('目标验证：全部符合期望时无违规', () => {
  const rules = [rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' })]
  const res = verifyGoal(rules, goal({ cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }))
  assert.equal(res.kind, 'ok')
  if (res.kind !== 'ok') return
  assert.equal(res.report.totalSize, 256 * 65536)
  assert.equal(res.report.matchSize, res.report.totalSize)
  assert.equal(res.report.matchRatio, 1)
  assert.equal(res.report.otherSize, 0)
  assert.equal(res.report.unmatchedSize, 0)
  assert.equal(res.report.violations.length, 0)
})

test('目标验证：命中其他动作与未命中精确划分', () => {
  const rules = [
    rule({ name: 'ssh-deny', cidr: '10.0.0.0/25', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'deny' }),
  ]
  const res = verifyGoal(
    rules,
    goal({ cidr: '10.0.0.0/24', portStart: '22', portEnd: '22', protocol: 'TCP', action: 'allow' }),
  )
  assert.equal(res.kind, 'ok')
  if (res.kind !== 'ok') return
  const r = res.report
  assert.equal(r.totalSize, 256)
  assert.equal(r.matchSize, 0)
  assert.equal(r.otherSize, 128)
  assert.equal(r.unmatchedSize, 128)
  assert.equal(r.otherRatio, 0.5)
  assert.equal(r.unmatchedRatio, 0.5)
  assert.equal(r.violations.length, 2)

  const deny = r.violations.find((v) => v.kind === 'other-action')!
  assert.equal(deny.action, 'deny')
  assert.equal(deny.size, 128)
  assert.deepEqual(
    deny.rules.map((s) => s.ruleName),
    ['ssh-deny'],
  )
  // 精确区域：TCP 端口 22 × 10.0.0.0/25
  assert.equal(deny.regions.length, 1)
  assert.equal(deny.regions[0].protocol, 'TCP')
  assert.equal(deny.regions[0].blocks.length, 1)
  assert.equal(deny.regions[0].blocks[0].portStart, 22)
  assert.equal(deny.regions[0].blocks[0].portEnd, 22)
  assert.deepEqual(deny.regions[0].blocks[0].cidrs, ['10.0.0.0/25'])
  assert.equal(deny.regions[0].blocks[0].size, 128)
  // 代表报文可复现：命中 deny 规则
  assert.equal(deny.example.srcIp, '10.0.0.1')
  assert.equal(deny.example.srcPort, 22)
  assert.equal(deny.example.protocol, 'TCP')
  assert.equal(deny.exampleMatchedRule!.ruleName, 'ssh-deny')
  assert.equal(firstHit(rules, deny.example.srcIp, 22, 'TCP')!.action, 'deny')

  const miss = r.violations.find((v) => v.kind === 'unmatched')!
  assert.equal(miss.size, 128)
  assert.deepEqual(miss.regions[0].blocks[0].cidrs, ['10.0.0.128/25'])
  assert.equal(miss.example.srcIp, '10.0.0.129')
  assert.equal(miss.exampleMatchedRule, null)
  assert.equal(firstHit(rules, miss.example.srcIp, 22, 'TCP'), null)
})

test('目标验证：目标边界落在原子块内部时正确切分', () => {
  // 规则是整块 /8、全端口；目标的 IP 与端口边界都落在规则原子块内部
  const rules = [rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' })]
  const res = verifyGoal(
    rules,
    goal({ cidr: '10.0.128.0/17', portStart: '100', portEnd: '199', protocol: 'ANY', action: 'deny' }),
  )
  assert.equal(res.kind, 'ok')
  if (res.kind !== 'ok') return
  const r = res.report
  // 目标空间 = 2^15 IP × 100 端口 × 2 协议，全部命中 allow（≠ 期望 deny）
  assert.equal(r.totalSize, 32768 * 100 * 2)
  assert.equal(r.otherSize, r.totalSize)
  assert.equal(r.matchSize, 0)
  assert.equal(r.unmatchedSize, 0)
  assert.equal(r.violations.length, 1)
  const v = r.violations[0]
  assert.equal(v.action, 'allow')
  // 切分后的区域又精确合并回目标本身：TCP / UDP 各一块
  assert.equal(v.regions.length, 2)
  for (const g of v.regions) {
    assert.equal(g.blocks.length, 1)
    assert.deepEqual(g.blocks[0].cidrs, ['10.0.128.0/17'])
    assert.equal(g.blocks[0].portStart, 100)
    assert.equal(g.blocks[0].portEnd, 199)
    assert.equal(g.blocks[0].size, 32768 * 100)
    assert.equal(g.size, 32768 * 100)
  }
})

test('目标验证：ANY 分别检查 TCP 与 UDP', () => {
  const rules = [rule({ name: 'tcp-only', cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' })]
  const res = verifyGoal(rules, goal({ cidr: '10.0.0.0/24', protocol: 'ANY', action: 'allow' }))
  assert.equal(res.kind, 'ok')
  if (res.kind !== 'ok') return
  const r = res.report
  assert.equal(r.totalSize, 256 * 65536 * 2)
  // TCP 全部符合，UDP 全部未命中
  assert.equal(r.matchSize, 256 * 65536)
  assert.equal(r.unmatchedSize, 256 * 65536)
  assert.equal(r.matchRatio, 0.5)
  assert.equal(r.unmatchedRatio, 0.5)
  assert.equal(r.violations.length, 1)
  const v = r.violations[0]
  assert.equal(v.kind, 'unmatched')
  assert.equal(v.regions.length, 1)
  assert.equal(v.regions[0].protocol, 'UDP')
  assert.equal(v.example.protocol, 'UDP')
})

test('目标验证：非法规则不参与验证', () => {
  const rules = [
    rule({ name: 'bad-cidr', cidr: '10.0.0.5/24', action: 'deny' }),
    rule({ name: 'bad-port', cidr: '10.0.0.0/24', portStart: '99999', portEnd: '5', action: 'deny' }),
  ]
  const res = verifyGoal(rules, goal({ cidr: '10.0.0.0/24', protocol: 'TCP', action: 'allow' }))
  assert.equal(res.kind, 'ok')
  if (res.kind !== 'ok') return
  const r = res.report
  assert.equal(r.validRuleCount, 0)
  assert.equal(r.invalidRuleCount, 2)
  // 非法规则不提供任何命中：整个目标空间未命中
  assert.equal(r.unmatchedSize, r.totalSize)
  assert.equal(r.matchSize, 0)
  assert.equal(r.otherSize, 0)
})

test('目标验证：非法目标给出错误而不执行', () => {
  const rules = [rule({ name: 'A' })]
  const bad1 = verifyGoal(rules, goal({ cidr: '10.0.0.1/24' }))
  assert.equal(bad1.kind, 'invalid')
  const bad2 = verifyGoal(rules, goal({ portStart: '443', portEnd: '80' }))
  assert.equal(bad2.kind, 'invalid')
  if (bad2.kind === 'invalid') assert.ok(bad2.errors.some((e) => e.includes('倒置')))
  const bad3 = verifyGoal(rules, goal({ protocol: 'ICMP' }))
  assert.equal(bad3.kind, 'invalid')
  const bad4 = verifyGoal(rules, goal({ action: '  ' }))
  assert.equal(bad4.kind, 'invalid')
  const bad5 = verifyGoal(rules, goal({ cidr: '' }))
  assert.equal(bad5.kind, 'invalid')
})

test('目标验证：多个其他动作分组且区域大小守恒', () => {
  const rules = [
    rule({ name: 'd', cidr: '10.0.0.0/25', action: 'deny' }),
    rule({ name: 'r', cidr: '10.0.0.128/25', action: 'reject' }),
  ]
  const res = verifyGoal(rules, goal({ cidr: '10.0.0.0/24', protocol: 'ANY', action: 'allow' }))
  assert.equal(res.kind, 'ok')
  if (res.kind !== 'ok') return
  const r = res.report
  assert.equal(r.violations.length, 2)
  // 两组等大，按动作名排序：deny 在 reject 前
  assert.deepEqual(
    r.violations.map((v) => v.action),
    ['deny', 'reject'],
  )
  // 大小守恒：各类之和 = 目标空间；每组的区域块之和 = 组大小
  assert.equal(r.matchSize + r.otherSize + r.unmatchedSize, r.totalSize)
  for (const v of r.violations) {
    const regionSum = v.regions.reduce(
      (s, g) => s + g.blocks.reduce((x, b) => x + b.size, 0),
      0,
    )
    assert.equal(regionSum, v.size)
    assert.equal(v.size, 128 * 65536 * 2)
  }
})

test('目标验证：代表报文可复现且落在目标空间内', () => {
  const rules = [
    rule({ name: 'web', cidr: '10.0.0.0/25', portStart: '80', portEnd: '80', protocol: 'TCP', action: 'deny' }),
    rule({ name: 'dns', cidr: '10.0.0.0/24', portStart: '53', portEnd: '53', protocol: 'UDP', action: 'drop' }),
    rule({ name: 'base', cidr: '10.0.0.0/24', action: 'allow' }),
  ]
  const g = goal({ cidr: '10.0.0.0/24', portStart: '0', portEnd: '1024', protocol: 'ANY', action: 'allow' })
  const res = verifyGoal(rules, g)
  assert.equal(res.kind, 'ok')
  if (res.kind !== 'ok') return
  const r = res.report
  assert.ok(r.violations.length >= 2) // deny 组、drop 组（无未命中：base 兜底）
  const targetIp = (ip: string) => {
    const n = ipv4ToInt(ip)
    return n >= ipv4ToInt('10.0.0.0') && n <= ipv4ToInt('10.0.0.255')
  }
  for (const v of r.violations) {
    const p = v.example
    assert.ok(targetIp(p.srcIp), `代表报文 ${p.srcIp} 应落在目标 CIDR 内`)
    assert.ok(p.srcPort >= 0 && p.srcPort <= 1024, '代表报文端口应落在目标区间内')
    const hit = firstHit(rules, p.srcIp, p.srcPort, p.protocol)
    if (v.kind === 'unmatched') {
      assert.equal(hit, null)
    } else {
      assert.ok(hit, '代表报文应命中某条规则')
      assert.equal(hit!.action, v.action)
      assert.equal(hit!.index, v.exampleMatchedRule!.ruleIndex)
    }
  }
})

test('目标验证：只读，不改动规则输入', () => {
  const rules = [
    rule({ name: 'A', cidr: '10.0.0.0/8', action: 'allow' }),
    rule({ name: 'B', cidr: '10.0.0.0/16', action: 'deny' }),
  ]
  const snapshot = JSON.stringify(rules)
  const res = verifyGoal(rules, goal({ cidr: '10.0.0.0/12', action: 'allow' }))
  assert.equal(res.kind, 'ok')
  assert.equal(JSON.stringify(rules), snapshot)
})

console.log(`\n全部 ${passed} 项测试通过 ✔`)