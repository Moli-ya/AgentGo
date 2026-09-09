import type {
  BrowserNetworkIntent,
  BrowserNetworkVerdict
} from '@agentgo/contracts'

export interface BrokeredBrowserRequest {
  readonly url: string
  readonly method: string
  readonly resourceType: string
  readonly headers: Readonly<Record<string, string>>
  readonly postData?: string
  readonly isNavigation: boolean
  readonly frameUrl?: string
  readonly pageUrl?: string
}

export interface BrowserNetworkBrokerFulfillment {
  readonly status: number
  readonly headers: Readonly<Record<string, string>>
  readonly body: Uint8Array
}

export interface BrowserNetworkBrokerDecision {
  readonly verdict: BrowserNetworkVerdict
  readonly reason: string
  readonly intent: BrowserNetworkIntent
  readonly fulfillment?: BrowserNetworkBrokerFulfillment
}

export interface BrowserNetworkBroker {
  handle(request: BrokeredBrowserRequest): Promise<BrowserNetworkBrokerDecision>
}

export interface BrokeredBrowserSessionInput {
  readonly startUrl: string
  readonly timeoutMs: number
  readonly signal?: AbortSignal
  readonly broker: BrowserNetworkBroker
}

export interface BrokeredBrowserSessionResult {
  readonly status: 'succeeded' | 'failed' | 'cancelled'
  readonly finalUrl: string
  readonly pageTitle?: string
  readonly blockedTransports: number
  readonly errorCode?: string
}

export interface BrokeredBrowserSession {
  run(input: BrokeredBrowserSessionInput): Promise<BrokeredBrowserSessionResult>
}
