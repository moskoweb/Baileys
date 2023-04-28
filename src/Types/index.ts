export * from './Auth'
export * from './GroupMetadata'
export * from './Chat'
export * from './Contact'
export * from './State'
export * from './Message'
export * from './Socket'
export * from './Events'
export * from './Product'
export * from './Call'
export * from './Signal'

import { AuthenticationState } from './Auth'
import { SocketConfig } from './Socket'

export type UserFacingSocketConfig = Partial<SocketConfig> & { auth: AuthenticationState }

export enum DisconnectReason {
    loggedOut = 401,
    connectionTerminated = 403,
    connectionLost = 408,
    timedOut = 408,
    multideviceMismatch = 411,
    connectionClosed = 428,
    connectionReplaced = 440,
    badSession = 500,
    banned = 503,
    restartRequired = 515,
}

export type WAInitResponse = {
    ref: string
    ttl: number
    status: 200
}

export type WABusinessHoursConfig = {
    day_of_week: string
    mode: string
    open_time?: number
    close_time?: number
}

export type WABusinessProfile = {
    description: string
    email: string | undefined
    business_hours: {
        timezone?: string
        config?: WABusinessHoursConfig[]
        business_config?: WABusinessHoursConfig[]
    }
    website: string[]
    category?: string
    wid?: string
    address?: string
}

export type CurveKeyPair = { private: Uint8Array, public: Uint8Array }