/**
 * 策略目标验证。
 *
 * 用户给定一个目标报文空间（IPv4 CIDR × 端口区间 × 协议）与期望动作，
 * 在首条命中语义下对当前规则做一次**只读**验证（不改动任何规则）。
 *
 * 做法：把目标边界作为额外切分插入原子空间——即使目标边界落在既有
 * 原子块内部，也会先被正确切开——随后逐个单元登记首命中者，把整个
 * 目标空间精确划分为三类：
 *
 *   - 符合期望：首命中规则的动作与期望动作一致
 *   - 命中其他动作：有规则命中但动作不同（违规区域按实际动作分组汇总）
 *   - 未命中任何规则
 *
 * 与审计一致的约定：非法规则不参与验证；协议 ANY 分别检查 TCP 与 UDP；
 * 每个违规分组给出确定性的可复现代表报文与精确的 CIDR / 端口矩形分解。
 */
import {
  CONCRETE_PROTOCOLS,
  PROTO_INDEX,
  atomCellSize,
  buildIpAtoms,
  buildOwnerMap,
  buildPortAtoms,
  containedIndices,
  exampleIpOf,
  mergeIpAtoms,
  validateRules,
} from './engine'
import { intToIpv4, parseCidrStrict } from './iputil'
import type { ParsedCidr } from './iputil'
import type {
  Action,
  GoalInput,
  GoalPacket,
  GoalRegionBlock,
  GoalRegionGroup,
  GoalVerification,
  GoalViolation,
  IpAtom,
  NormalizedRule,
  PortAtom,
  Protocol,
  RuleInput,
} from './types'

// ---------------------------------------------------------------------------
// 目标校验（与规则校验同一套严格语义）
// ---------------------------------------------------------------------------

type GoalChecked =
  | {
      ok: true
      cidr: ParsedCidr
      portStart: number
      portEnd: number
      protocol: Protocol
      action: Action
    }
  | { ok: false; errors: string[] }

function validateGoal(goal: GoalInput): GoalChecked {
  const errors: string[] = []

  let cidr: ParsedCidr | null = null
  if (!goal.cidr.trim()) {
    errors.push('目标 CIDR 不能为空')
  } else {
    try {
      cidr = parseCidrStrict(goal.cidr)
    } catch (err) {
      errors.push((err as Error).message)
    }
  }

  const pStartText = String(goal.portStart).trim()
  const pEndText = String(goal.portEnd).trim()
  let portStart = NaN
  let portEnd = NaN
  if (pStartText === '') {
    errors.push('起始端口不能为空')
  } else if (!/^\d+$/.test(pStartText)) {
    errors.push('起始端口必须为整数')
  } else {
    portStart = Number(pStartText)
    if (portStart < 0 || portStart > 65535) errors.push('起始端口必须在 0-65535 之间')
  }
  if (pEndText === '') {
    errors.push('结束端口不能为空')
  } else if (!/^\d+$/.test(pEndText)) {
    errors.push('结束端口必须为整数')
  } else {
    portEnd = Number(pEndText)
    if (portEnd < 0 || portEnd > 65535) errors.push('结束端口必须在 0-65535 之间')
  }
  if (!Number.isNaN(portStart) && !Number.isNaN(portEnd) && portStart > portEnd) {
    errors.push(`端口区间倒置：${portStart} > ${portEnd}`)
  }

  let protocol: Protocol | null = null
  const protoUpper = goal.protocol.trim().toUpperCase()
  if (!protoUpper) {
    errors.push('协议不能为空')
  } else if (protoUpper !== 'TCP' && protoUpper !== 'UDP' && protoUpper !== 'ANY') {
    errors.push(`协议必须为 TCP / UDP / ANY，收到 “${goal.protocol}”`)
  } else {
    protocol = protoUpper as Protocol
  }

  const action = goal.action.trim()
  if (!action) errors.push('期望动作不能为空')

  if (errors.length > 0 || !cidr || protocol === null) {
    return { ok: false, errors }
  }
  return { ok: true, cidr, portStart, portEnd, protocol, action }
}

// ---------------------------------------------------------------------------
// 精确区域分解与代表报文
// ---------------------------------------------------------------------------

function decodeKey(key: string): [number, number, number] {
  const [ip, port, proto] = key.split('.').map(Number)
  return [ip, port, proto]
}

/**
 * 把一组单元精确分解为「端口区间 × CIDR 列表」的矩形块（按协议分组）。
 * 同一协议下，端口相邻且 IP 集合完全相同的行会被合并；
 * 块与块互斥、并集恰好等于输入单元集合，因此大小精确守恒。
 */
function exactRegions(
  keys: string[],
  ipAtoms: IpAtom[],
  portAtoms: PortAtom[],
): GoalRegionGroup[] {
  // proto -> portIdx -> ipIdx[]（keys 按 (ip, port, proto) 升序生成，ips 天然升序）
  const byProto = new Map<number, Map<number, number[]>>()
  for (const key of keys) {
    const [ip, port, proto] = decodeKey(key)
    let pm = byProto.get(proto)
    if (!pm) {
      pm = new Map()
      byProto.set(proto, pm)
    }
    const arr = pm.get(port)
    if (arr) arr.push(ip)
    else pm.set(port, [ip])
  }

  const groups: GoalRegionGroup[] = []
  for (const proto of [0, 1]) {
    const pm = byProto.get(proto)
    if (!pm) continue
    const blocks: GoalRegionBlock[] = []
    let size = 0
    let cur: { ports: number[]; ips: number[] } | null = null
    const flush = () => {
      if (!cur) return
      const cidrs = mergeIpAtoms(cur.ips, ipAtoms)
      const ipCount = cur.ips.reduce(
        (sum, i) => sum + (ipAtoms[i].end - ipAtoms[i].start + 1),
        0,
      )
      const portStart = portAtoms[cur.ports[0]].start
      const portEnd = portAtoms[cur.ports[cur.ports.length - 1]].end
      const blockSize = ipCount * (portEnd - portStart + 1)
      blocks.push({ portStart, portEnd, cidrs, size: blockSize })
      size += blockSize
    }
    const portIndices = [...pm.keys()].sort((a, b) => a - b)
    for (const p of portIndices) {
      const ips = pm.get(p)!
      const sameIps =
        cur !== null &&
        cur.ips.length === ips.length &&
        cur.ips.every((v, i) => v === ips[i])
      if (cur && sameIps && p === cur.ports[cur.ports.length - 1] + 1) {
        cur.ports.push(p)
      } else {
        flush()
        cur = { ports: [p], ips }
      }
    }
    flush()
    groups.push({ protocol: CONCRETE_PROTOCOLS[proto], blocks, size })
  }
  return groups
}

/** 由单元 key 生成确定性的可复现代表报文（与引擎示例报文选点规则一致） */
function packetFor(key: string, ipAtoms: IpAtom[], portAtoms: PortAtom[]): GoalPacket {
  const [ip, port, proto] = decodeKey(key)
  return {
    srcIp: intToIpv4(exampleIpOf(ipAtoms[ip])),
    srcPort: portAtoms[port].start,
    protocol: CONCRETE_PROTOCOLS[proto],
  }
}

// ---------------------------------------------------------------------------
// 主验证流程
// ---------------------------------------------------------------------------

/**
 * 对当前规则执行一次只读的目标验证。
 * @param inputs 当前规则（不会被修改；非法规则按既有语义排除）
 * @param goal   目标空间与期望动作
 */
export function verifyGoal(
  inputs: RuleInput[],
  goal: GoalInput,
  now: Date = new Date(),
): GoalVerification {
  const g = validateGoal(goal)
  if (!g.ok) return { kind: 'invalid', errors: g.errors }

  const { valid, invalid } = validateRules(inputs)

  // 目标边界参与原子划分：把目标伪装成一条“规则”加入原子空间构建，
  // 即使目标边界落在既有原子块内部，也会被精确切开（不影响命中计算，
  // 因为 owner map 只用真正的规则构建）。
  const target: NormalizedRule = {
    id: '__goal_target__',
    name: '（验证目标）',
    index: -1,
    ipStart: g.cidr.start,
    ipEnd: g.cidr.end,
    prefix: g.cidr.prefix,
    cidrText: g.cidr.canonical,
    portStart: g.portStart,
    portEnd: g.portEnd,
    protocol: 'ANY',
    action: '',
    enabled: true,
  }
  const ipAtoms = buildIpAtoms([...valid, target])
  const portAtoms = buildPortAtoms([...valid, target])
  const owner = buildOwnerMap(valid, ipAtoms, portAtoms)

  const ipIdx = containedIndices(ipAtoms, g.cidr.start, g.cidr.end)
  const portIdx = containedIndices(portAtoms, g.portStart, g.portEnd)
  const protoIdx = PROTO_INDEX.get(g.protocol)!

  let matchSize = 0
  const otherGroups = new Map<
    Action,
    { size: number; cells: number; keys: string[]; rules: Map<number, number> }
  >()
  let unmatchedSize = 0
  const unmatchedKeys: string[] = []

  // 按 (ip, port, proto) 升序遍历目标空间内的全部单元，keys 数组天然有序
  for (const ip of ipIdx) {
    for (const port of portIdx) {
      const size = atomCellSize(ipAtoms[ip], portAtoms[port])
      for (const proto of protoIdx) {
        const key = `${ip}.${port}.${proto}`
        const pos = owner.get(key)
        if (pos === undefined) {
          unmatchedSize += size
          unmatchedKeys.push(key)
          continue
        }
        const rule = valid[pos]
        if (rule.action === g.action) {
          matchSize += size
          continue
        }
        let grp = otherGroups.get(rule.action)
        if (!grp) {
          grp = { size: 0, cells: 0, keys: [], rules: new Map() }
          otherGroups.set(rule.action, grp)
        }
        grp.size += size
        grp.cells++
        grp.keys.push(key)
        grp.rules.set(pos, (grp.rules.get(pos) ?? 0) + 1)
      }
    }
  }

  const otherSize = [...otherGroups.values()].reduce((sum, x) => sum + x.size, 0)
  const totalSize = matchSize + otherSize + unmatchedSize

  const violations: GoalViolation[] = []
  const sortedGroups = [...otherGroups.entries()].sort(
    (a, b) => b[1].size - a[1].size || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0),
  )
  for (const [action, grp] of sortedGroups) {
    const firstKey = grp.keys[0]
    const hit = valid[owner.get(firstKey)!]
    violations.push({
      kind: 'other-action',
      action,
      size: grp.size,
      ratio: totalSize === 0 ? 0 : grp.size / totalSize,
      cells: grp.cells,
      rules: [...grp.rules.entries()]
        .map(([pos, cells]) => ({
          ruleIndex: valid[pos].index,
          ruleName: valid[pos].name,
          cells,
        }))
        .sort((a, b) => b.cells - a.cells || a.ruleIndex - b.ruleIndex),
      regions: exactRegions(grp.keys, ipAtoms, portAtoms),
      example: packetFor(firstKey, ipAtoms, portAtoms),
      exampleMatchedRule: { ruleIndex: hit.index, ruleName: hit.name },
    })
  }
  if (unmatchedKeys.length > 0) {
    violations.push({
      kind: 'unmatched',
      action: null,
      size: unmatchedSize,
      ratio: totalSize === 0 ? 0 : unmatchedSize / totalSize,
      cells: unmatchedKeys.length,
      rules: [],
      regions: exactRegions(unmatchedKeys, ipAtoms, portAtoms),
      example: packetFor(unmatchedKeys[0], ipAtoms, portAtoms),
      exampleMatchedRule: null,
    })
  }

  return {
    kind: 'ok',
    report: {
      generatedAt: now.toISOString(),
      goal: {
        cidrText: g.cidr.canonical,
        portStart: g.portStart,
        portEnd: g.portEnd,
        protocol: g.protocol,
        action: g.action,
      },
      totalSize,
      matchSize,
      matchRatio: totalSize === 0 ? 0 : matchSize / totalSize,
      otherSize,
      otherRatio: totalSize === 0 ? 0 : otherSize / totalSize,
      unmatchedSize,
      unmatchedRatio: totalSize === 0 ? 0 : unmatchedSize / totalSize,
      violations,
      validRuleCount: valid.length,
      invalidRuleCount: invalid.length,
    },
  }
}
