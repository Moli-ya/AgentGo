import { join } from 'node:path'
import { app, BrowserWindow, ipcMain } from 'electron'
import { createDefaultScanPlan } from '@agentgo/agent-runtime'
import {
  IPC_CHANNELS,
  type BootstrapState,
  type PolicySelfCheckResult,
  type ProbeAction,
  type TargetScope
} from '@agentgo/contracts'
import { evaluateProbe } from '@agentgo/security-policy'

const plan = createDefaultScanPlan()
const isSmokeTest = process.env.AGENTGO_SMOKE_TEST === '1'

function getBootstrapState(): BootstrapState {
  return {
    appVersion: app.getVersion(),
    milestone: 'M0',
    projectStatus: '架构骨架已建立，主动探测策略处于可验证状态',
    agents: ['planner', 'knowledge', 'strategy', 'analysis', 'verifier'],
    phases: plan.phases,
    vulnerabilityFamilies: plan.families,
    safeguards: [
      '所有主动动作经过确定性 SecurityPolicy',
      'L1 低影响探测允许，L2 逐次批准',
      'DROP/DELETE/持久化/越界等 L3 动作永久拒绝',
      'Confirmed 结论必须绑定规则和证据'
    ]
  }
}

function runPolicySelfCheck(): PolicySelfCheckResult {
  const scope: TargetScope = {
    id: 'desktop-self-check',
    allowedOrigins: ['https://lab.example.test'],
    allowedPathPrefixes: ['/'],
    allowActiveProbing: true,
    allowSensitiveProbing: false,
    maxRequestsPerMinute: 30,
    maxConcurrency: 2
  }

  const safeProbe: ProbeAction = {
    id: 'safe-probe',
    kind: 'http-request',
    targetUrl: 'https://lab.example.test/search?q=agentgo-marker',
    method: 'GET',
    probeLevel: 'active-safe',
    sideEffect: 'none',
    summary: '使用惰性标记比较授权靶场响应差异',
    expectedEvidence: '基线和测试响应摘要',
    requestedRequestsPerMinute: 5,
    requestedConcurrency: 1,
    userApproved: false
  }

  const destructiveProbe: ProbeAction = {
    id: 'destructive-probe',
    kind: 'http-request',
    targetUrl: 'https://lab.example.test/api/query',
    method: 'POST',
    probeLevel: 'destructive',
    sideEffect: 'destructive',
    summary: '尝试执行破坏性数据库语句',
    payloadSummary: 'DROP TABLE users',
    expectedEvidence: '该动作不应执行',
    userApproved: true
  }

  return {
    safeProbe: evaluateProbe(safeProbe, scope),
    destructiveProbe: evaluateProbe(destructiveProbe, scope),
    note: '自检只评估策略，不会向任何目标发送网络请求。'
  }
}

function registerIpcHandlers(): void {
  ipcMain.handle(IPC_CHANNELS.getBootstrapState, () => getBootstrapState())
  ipcMain.handle(IPC_CHANNELS.runPolicySelfCheck, () => runPolicySelfCheck())

  if (isSmokeTest) {
    const smokeTimeout = setTimeout(() => {
      console.error('AGENTGO_SMOKE_TEST_RENDERER_TIMEOUT')
      app.exit(1)
    }, 15_000)

    ipcMain.once(IPC_CHANNELS.rendererReady, () => {
      clearTimeout(smokeTimeout)
      const result = runPolicySelfCheck()
      const passed = result.safeProbe.allowed && !result.destructiveProbe.allowed
      console.log(
        passed
          ? 'AGENTGO_SMOKE_TEST_OK'
          : 'AGENTGO_SMOKE_TEST_FAILED'
      )
      app.exit(passed ? 0 : 1)
    })
  }
}

function createWindow(): void {
  const window = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 980,
    minHeight: 640,
    show: false,
    backgroundColor: '#0b1220',
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false
    }
  })

  if (!isSmokeTest) {
    window.once('ready-to-show', () => window.show())
  }
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))

  const devUrl = process.env.ELECTRON_RENDERER_URL

  window.webContents.on('will-navigate', (event, url) => {
    const allowed = devUrl ? url.startsWith(devUrl) : url.startsWith('file://')
    if (!allowed) {
      event.preventDefault()
    }
  })

  if (isSmokeTest) {
    window.webContents.once(
      'did-fail-load',
      (_event, errorCode, errorDescription) => {
        console.error('AGENTGO_SMOKE_TEST_LOAD_FAILED', errorCode, errorDescription)
        app.exit(1)
      }
    )
  }

  if (devUrl) {
    void window.loadURL(devUrl)
  } else {
    void window.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

app.whenReady().then(() => {
  registerIpcHandlers()
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
