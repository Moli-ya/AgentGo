import { useEffect, useState } from 'react'
import type {
  BootstrapState,
  PolicyDecision,
  PolicySelfCheckResult,
  VulnerabilityFamily
} from '@agentgo/contracts'
import { getDesktopApi } from './desktop-api'

const familyLabels: Record<VulnerabilityFamily, string> = {
  sqli: 'SQL 注入',
  xss: 'XSS',
  ssrf: 'SSRF',
  idor: '越权 / IDOR'
}

const familyMeta: Record<
  VulnerabilityFamily,
  { code: string; note: string; tone: string }
> = {
  sqli: {
    code: 'SQL',
    note: '非写入式差异验证',
    tone: 'blue'
  },
  xss: {
    code: 'JS',
    note: '惰性标记与隔离确认',
    tone: 'violet'
  },
  ssrf: {
    code: 'URL',
    note: '受控回连与边界检查',
    tone: 'orange'
  },
  idor: {
    code: 'ID',
    note: '双身份只读对照',
    tone: 'green'
  }
}

const navItems = [
  { label: '工作台', icon: 'dashboard', active: true },
  { label: '目标', icon: 'target', active: false },
  { label: '扫描任务', icon: 'scan', active: false },
  { label: 'Agent 控制台', icon: 'agents', active: false },
  { label: '知识库', icon: 'book', active: false },
  { label: 'Findings', icon: 'finding', active: false },
  { label: '设置', icon: 'settings', active: false }
] as const

type IconName = (typeof navItems)[number]['icon']

const iconPaths: Record<IconName, string[]> = {
  dashboard: ['M4 4h6v6H4z', 'M14 4h6v10h-6z', 'M4 14h6v6H4z', 'M14 18h6v2h-6z'],
  target: ['M12 3a9 9 0 1 0 9 9', 'M12 7a5 5 0 1 0 5 5', 'M12 10a2 2 0 1 0 2 2'],
  scan: ['M5 3H3v5', 'M19 3h2v5', 'M5 21H3v-5', 'M19 21h2v-5', 'M7 12h10'],
  agents: ['M8 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6', 'M16 10a2.5 2.5 0 1 0 0-5', 'M3 20v-2a5 5 0 0 1 10 0v2', 'M14 14a4 4 0 0 1 7 3v3'],
  book: ['M4 4h6a3 3 0 0 1 3 3v13H7a3 3 0 0 0-3 1z', 'M20 4h-4a3 3 0 0 0-3 3v13h4a3 3 0 0 1 3 1z'],
  finding: ['M5 3h10l4 4v14H5z', 'M15 3v5h4', 'M8 13h8', 'M8 17h5'],
  settings: ['M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6', 'M19 13.5v-3l-2-.8-.7-1.7.8-2-2.1-2.1-2 .8-1.7-.7-.8-2h-3l-.8 2-1.7.7-2-.8L.9 6l.8 2-.7 1.7-2 .8v3l2 .8.7 1.7-.8 2L3 20.1l2-.8 1.7.7.8 2h3l.8-2 1.7-.7 2 .8 2.1-2.1-.8-2 .7-1.7z']
}

function NavIcon({ name }: { name: IconName }): React.JSX.Element {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      {iconPaths[name].map((path) => (
        <path key={path} d={path} />
      ))}
    </svg>
  )
}

function AgentFlow(): React.JSX.Element {
  const plannerToKnowledge = 'M104 130 C150 130 164 70 218 70'
  const plannerToStrategy = 'M104 130 C150 130 164 192 218 192'
  const knowledgeToAnalysis = 'M272 70 C326 70 332 130 382 130'
  const strategyToAnalysis = 'M272 192 C326 192 332 130 382 130'
  const analysisToVerifier = 'M438 130 C476 130 492 130 520 130'

  return (
    <div className="flow-visual" aria-label="五 Agent 协作矢量动画">
      <svg viewBox="0 0 620 260" role="img">
        <path className="flow-line" d={plannerToKnowledge} />
        <path className="flow-line" d={plannerToStrategy} />
        <path className="flow-line" d={knowledgeToAnalysis} />
        <path className="flow-line" d={strategyToAnalysis} />
        <path className="flow-line" d={analysisToVerifier} />

        <circle className="flow-packet packet-blue" r="4">
          <animateMotion dur="4.8s" repeatCount="indefinite" path={plannerToKnowledge} />
        </circle>
        <circle className="flow-packet packet-violet" r="4">
          <animateMotion
            begin="1.2s"
            dur="4.6s"
            repeatCount="indefinite"
            path={plannerToStrategy}
          />
        </circle>
        <circle className="flow-packet packet-green" r="4">
          <animateMotion
            begin="0.8s"
            dur="4s"
            repeatCount="indefinite"
            path={knowledgeToAnalysis}
          />
        </circle>
        <circle className="flow-packet packet-orange" r="4">
          <animateMotion
            begin="2.1s"
            dur="4.2s"
            repeatCount="indefinite"
            path={strategyToAnalysis}
          />
        </circle>
        <circle className="flow-packet packet-blue" r="4">
          <animateMotion
            begin="1.5s"
            dur="3.4s"
            repeatCount="indefinite"
            path={analysisToVerifier}
          />
        </circle>

        <g className="flow-node planner-node" transform="translate(76 130)">
          <circle r="30" />
          <text y="-2">Plan</text>
          <text className="node-subtitle" y="13">规划</text>
        </g>
        <g className="flow-node knowledge-node" transform="translate(246 70)">
          <circle r="30" />
          <text y="-2">Know</text>
          <text className="node-subtitle" y="13">知识</text>
        </g>
        <g className="flow-node strategy-node" transform="translate(246 192)">
          <circle r="30" />
          <text y="-2">Test</text>
          <text className="node-subtitle" y="13">策略</text>
        </g>
        <g className="flow-node analysis-node" transform="translate(410 130)">
          <circle r="30" />
          <text y="-2">Read</text>
          <text className="node-subtitle" y="13">分析</text>
        </g>
        <g className="flow-node verifier-node" transform="translate(550 130)">
          <circle r="30" />
          <circle className="node-pulse" r="39" />
          <text y="-2">Verify</text>
          <text className="node-subtitle" y="13">复核</text>
        </g>
      </svg>
      <div className="flow-caption">
        <span><i className="legend-dot blue" />结构化上下文</span>
        <span><i className="legend-dot green" />证据与规则</span>
      </div>
    </div>
  )
}

function Decision({
  title,
  decision
}: {
  title: string
  decision: PolicyDecision
}): React.JSX.Element {
  return (
    <article className={`decision ${decision.allowed ? 'allowed' : 'blocked'}`}>
      <div className="decision-title">
        <span>{title}</span>
        <strong>{decision.allowed ? '允许执行' : '已拦截'}</strong>
      </div>
      <code>{decision.code}</code>
      <p>{decision.reasons.join('；')}</p>
    </article>
  )
}

export function App(): React.JSX.Element {
  const desktopApi = getDesktopApi()
  const [state, setState] = useState<BootstrapState>()
  const [selfCheck, setSelfCheck] = useState<PolicySelfCheckResult>()
  const [error, setError] = useState<string>()
  const [checking, setChecking] = useState(false)

  useEffect(() => {
    desktopApi
      .getBootstrapState()
      .then((bootstrapState) => {
        setState(bootstrapState)
        desktopApi.notifyRendererReady()
      })
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : '无法读取应用状态')
      })
  }, [desktopApi])

  async function runSelfCheck(): Promise<void> {
    setChecking(true)
    setError(undefined)
    try {
      setSelfCheck(await desktopApi.runPolicySelfCheck())
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '策略自检失败')
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="app-frame">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 32 32">
              <path d="M7 22 16 5l9 17" />
              <path d="M10 17h12" />
              <circle cx="16" cy="25" r="2.5" />
            </svg>
          </div>
          <div>
            <strong>AgentGo</strong>
            <span>Security Studio</span>
          </div>
        </div>

        <nav aria-label="主导航">
          {navItems.map((item) => (
            <button
              className={item.active ? 'nav-item active' : 'nav-item'}
              type="button"
              key={item.label}
              aria-current={item.active ? 'page' : undefined}
            >
              <NavIcon name={item.icon} />
              <span>{item.label}</span>
              {!item.active ? <small>即将开放</small> : null}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="local-state">
            <span className="live-dot" />
            <div>
              <strong>本地运行</strong>
              <small>数据未离开设备</small>
            </div>
          </div>
          <p>仅限授权目标</p>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div>
            <span className="breadcrumb">工作区 /</span>
            <strong>项目总览</strong>
          </div>
          <div className="topbar-actions">
            <span className="status-chip">
              <i />
              SecurityPolicy 在线
            </span>
            <div className="avatar">AG</div>
          </div>
        </header>

        <div className="content">
          {error ? <div className="error">{error}</div> : null}

          <section className="hero-card">
            <div className="hero-copy">
              <div className="section-label">M0 · ARCHITECTURE SKELETON</div>
              <h1>让主动验证有证据，也有边界。</h1>
              <p>
                五个 Agent 负责规划、知识、策略、分析和复核；确定性策略层负责阻止越界与破坏性动作。
              </p>
              <div className="hero-status">
                <span className="milestone-badge">{state?.milestone ?? 'M0'}</span>
                <span>{state?.projectStatus ?? '正在连接 Main Process…'}</span>
              </div>
            </div>
            <AgentFlow />
          </section>

          <section className="family-grid" aria-label="V1 漏洞覆盖">
            {state?.vulnerabilityFamilies.map((family) => {
              const meta = familyMeta[family]
              return (
                <article className="family-card" key={family}>
                  <div className={`family-code ${meta.tone}`}>{meta.code}</div>
                  <div>
                    <strong>{familyLabels[family]}</strong>
                    <p>{meta.note}</p>
                  </div>
                  <span className="ready-mark">已建模</span>
                </article>
              )
            })}
          </section>

          <section className="dashboard-grid">
            <article className="panel workflow-panel">
              <div className="panel-heading">
                <div>
                  <span className="section-label">GATED WORKFLOW</span>
                  <h2>SRC 研究流程</h2>
                </div>
                <span className="count-badge">{state?.phases.length ?? 0} 阶段</span>
              </div>
              <div className="workflow-list">
                {state?.phases.map((phase, index) => (
                  <div className="workflow-step" key={phase}>
                    <div className="step-index">{String(index + 1).padStart(2, '0')}</div>
                    <div className="step-track">
                      <span />
                    </div>
                    <div>
                      <strong>{phase}</strong>
                      <small>{index < 2 ? '信息与范围' : index < 5 ? '主动研究' : '证据与结论'}</small>
                    </div>
                  </div>
                ))}
              </div>
            </article>

            <article className="panel agent-panel">
              <div className="panel-heading">
                <div>
                  <span className="section-label">CORE ROLES</span>
                  <h2>Agent 编排</h2>
                </div>
                <span className="count-badge">{state?.agents.length ?? 0} Agents</span>
              </div>
              <div className="agent-stack">
                {state?.agents.map((agent, index) => (
                  <div className="agent-row" key={agent}>
                    <span className={`agent-number tone-${index + 1}`}>
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <div>
                      <strong>{agent}</strong>
                      <small>{['计划与预算', '来源与规则', '验证假设', '差异与信号', '独立结论'][index]}</small>
                    </div>
                    <i className="row-status" />
                  </div>
                ))}
              </div>
            </article>

            <article className="panel policy-panel">
              <div className="panel-heading">
                <div>
                  <span className="section-label">DETERMINISTIC GATE</span>
                  <h2>SecurityPolicy 自检</h2>
                </div>
                <button type="button" onClick={runSelfCheck} disabled={checking}>
                  {checking ? '检查中…' : '运行自检'}
                </button>
              </div>
              <p className="panel-description">
                只在 Main Process 中评估两份 Proposal，不发送网络请求。预期结果是安全主动探测通过，DROP 动作被硬拦截。
              </p>
              {selfCheck ? (
                <div className="decision-grid">
                  <Decision title="低影响主动探测" decision={selfCheck.safeProbe} />
                  <Decision title="数据库 DROP 动作" decision={selfCheck.destructiveProbe} />
                </div>
              ) : (
                <div className="policy-placeholder">
                  <svg viewBox="0 0 32 32" aria-hidden="true">
                    <path d="M16 3 27 7v8c0 7-4.5 11.5-11 14-6.5-2.5-11-7-11-14V7z" />
                    <path d="m11 16 3 3 7-8" />
                  </svg>
                  <div>
                    <strong>安全门禁等待验证</strong>
                    <span>点击“运行自检”查看确定性决策结果</span>
                  </div>
                </div>
              )}
            </article>

            <article className="panel guardrail-panel">
              <span className="section-label">NON-NEGOTIABLE</span>
              <h2>研究底线</h2>
              <ul>
                {state?.safeguards.map((item) => (
                  <li key={item}>
                    <span>✓</span>
                    {item}
                  </li>
                ))}
              </ul>
            </article>
          </section>
        </div>
      </main>
    </div>
  )
}
