import { useMemo, useState } from 'react'
import { verifyGoal } from './audit/goal'
import type { GoalReport, GoalViolation, RuleInput } from './audit/types'
import { CopyButton } from './CopyButton'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

const PROTOCOL_OPTIONS = ['TCP', 'UDP', 'ANY']

function ViolationCard({ violation }: { violation: GoalViolation }) {
  const unmatched = violation.kind === 'unmatched'
  return (
    <div className={`violation-card ${unmatched ? 'unmatched' : ''}`}>
      <div className="violation-head">
        <span className="violation-title">
          {unmatched ? '未命中任何规则' : '命中其他动作'}
        </span>
        {!unmatched && <span className="action-pill">{violation.action}</span>}
        <span style={{ flex: 1 }} />
        <span className="muted-text">
          {formatSize(violation.size)} 条报文空间 · 占目标 {formatPercent(violation.ratio)}
        </span>
      </div>

      {violation.rules.length > 0 && (
        <div style={{ marginTop: 6 }}>
          {violation.rules.map((r) => (
            <div className="source-row" key={r.ruleIndex}>
              <span className="src-idx">#{r.ruleIndex + 1}</span>
              <span>{r.ruleName}</span>
              <span className="spacer" />
              <span className="muted-text">{r.cells} 个单元</span>
            </div>
          ))}
        </div>
      )}

      <div className="packet-box" style={{ marginTop: 8 }}>
        <span className={`tag ${unmatched ? 'unmatched' : 'other-action'}`}>代表报文</span>
        <span>{formatPacket(violation.example)}</span>
        <span className="arrow-note">
          {violation.exampleMatchedRule
            ? `→ 命中 #${violation.exampleMatchedRule.ruleIndex + 1} ${violation.exampleMatchedRule.ruleName}（${violation.action}）`
            : '→ 无任何规则命中'}
        </span>
        <CopyButton text={formatPacket(violation.example)} />
      </div>

      <div className="code-list" style={{ marginTop: 8 }}>
        {violation.regions.map((g) => (
          <div key={g.protocol} className="line">
            <strong>{g.protocol}</strong>
            <span className="muted-text"> · {formatSize(g.size)} 条报文空间</span>
            {g.blocks.map((b, i) => (
              <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
                端口 {formatPortRange(b.portStart, b.portEnd)} × {b.cidrs.join(', ')}（
                {formatSize(b.size)}）
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

function GoalResultView({ report }: { report: GoalReport }) {
  const allMatch = report.otherSize === 0 && report.unmatchedSize === 0
  return (
    <div style={{ marginTop: 14 }}>
      <div className="goal-summary">
        <div className="stat-card">
          <div className="label">目标报文空间</div>
          <div className="value" style={{ fontSize: 18 }}>
            {formatSize(report.totalSize)}
          </div>
          <div className="label" style={{ marginTop: 2 }}>
            {report.goal.cidrText} · 端口{' '}
            {formatPortRange(report.goal.portStart, report.goal.portEnd)} ·{' '}
            {report.goal.protocol}
          </div>
        </div>
        <div className="stat-card ok">
          <div className="label">符合期望（{report.goal.action}）</div>
          <div className="value">{formatPercent(report.matchRatio)}</div>
          <div className="label">{formatSize(report.matchSize)}</div>
        </div>
        <div className="stat-card danger">
          <div className="label">命中其他动作</div>
          <div className="value">{formatPercent(report.otherRatio)}</div>
          <div className="label">{formatSize(report.otherSize)}</div>
        </div>
        <div className="stat-card warn">
          <div className="label">未命中任何规则</div>
          <div className="value">{formatPercent(report.unmatchedRatio)}</div>
          <div className="label">{formatSize(report.unmatchedSize)}</div>
        </div>
      </div>

      {report.invalidRuleCount > 0 && (
        <div className="notice info">
          已按既有语义排除 {report.invalidRuleCount} 条非法规则（不参与验证）。
        </div>
      )}

      {allMatch ? (
        <div className="notice success">
          ✔ 整个目标空间的首命中动作均为「{report.goal.action}」，符合期望。
        </div>
      ) : (
        <div>
          <div className="legend" style={{ marginBottom: 8 }}>
            违规区域按实际动作汇总如下（未命中任何规则的流量单列一组）；
            每组给出可复制的代表报文与精确的 CIDR / 端口区域。
          </div>
          {report.violations.map((v, i) => (
            <ViolationCard key={`${v.kind}-${v.action ?? ''}-${i}`} violation={v} />
          ))}
        </div>
      )}
    </div>
  )
}

/**
 * 策略目标验证面板。
 * 结果通过 useMemo 依赖规则状态：规则编辑、导入、清空或调序确认后自动刷新；
 * 验证本身只读，不改动任何规则。
 */
export function GoalPanel({ rules }: { rules: RuleInput[] }) {
  const [cidr, setCidr] = useState('10.0.0.0/8')
  const [portStart, setPortStart] = useState('0')
  const [portEnd, setPortEnd] = useState('65535')
  const [protocol, setProtocol] = useState('ANY')
  const [action, setAction] = useState('allow')
  const [hasRun, setHasRun] = useState(false)

  const result = useMemo(
    () => (hasRun ? verifyGoal(rules, { cidr, portStart, portEnd, protocol, action }) : null),
    [rules, cidr, portStart, portEnd, protocol, action, hasRun],
  )

  return (
    <div className="panel">
      <div className="goal-form">
        <div className="goal-field">
          <label>目标 IPv4 CIDR</label>
          <input
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="10.0.0.0/8"
            spellCheck={false}
          />
        </div>
        <div className="goal-field">
          <label>目标端口区间</label>
          <div className="goal-ports">
            <input
              value={portStart}
              onChange={(e) => setPortStart(e.target.value)}
              placeholder="0"
            />
            <span className="muted-text">–</span>
            <input
              value={portEnd}
              onChange={(e) => setPortEnd(e.target.value)}
              placeholder="65535"
            />
          </div>
        </div>
        <div className="goal-field">
          <label>协议</label>
          <select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            {PROTOCOL_OPTIONS.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
        </div>
        <div className="goal-field">
          <label>期望动作</label>
          <input
            value={action}
            onChange={(e) => setAction(e.target.value)}
            placeholder="allow / deny"
          />
        </div>
        <div className="goal-field">
          <button className="primary" onClick={() => setHasRun(true)}>
            执行验证
          </button>
        </div>
      </div>

      <p className="legend">
        只读验证，不改动规则；结果在规则编辑或调序确认后自动刷新。
        非法规则不参与验证；协议 ANY 将分别检查 TCP 与 UDP；期望动作与规则动作按文本精确比较。
      </p>

      {!result && (
        <div className="notice info" style={{ marginTop: 10 }}>
          填写目标空间与期望动作后点击「执行验证」，将按首命中语义把整个目标空间精确划分为
          「符合期望 / 命中其他动作 / 未命中任何规则」三类。
        </div>
      )}

      {result?.kind === 'invalid' && (
        <div className="notice error" style={{ marginTop: 10 }}>
          <strong>验证目标非法，未执行：</strong>
          <ul className="error-list" style={{ marginTop: 6, marginBottom: 2 }}>
            {result.errors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        </div>
      )}

      {result?.kind === 'ok' && <GoalResultView report={result.report} />}
    </div>
  )
}
