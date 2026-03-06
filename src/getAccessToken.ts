import axios from 'axios'
import { wrapper } from 'axios-cookiejar-support'
import * as cheerio from 'cheerio'
import pkg from 'lodash'
import { Issuer } from 'openid-client'
import { CookieJar } from 'tough-cookie'

import { OAUTH2_CLIENT_ID, OAUTH2_CLIENT_SECRET, OAUTH2_REDIRECT_URI, LOGIN_URL } from './settings.js'

const { keyBy, mapValues } = pkg

const AUTH_TIMEOUT = 15000
const MAX_REDIRECT_DEPTH = 5

const oidcClient = Issuer.discover('https://accounts.brillion.geappliances.com/').then(
  geData =>
    new geData.Client({
      client_id: OAUTH2_CLIENT_ID,
      client_secret: OAUTH2_CLIENT_SECRET,
      response_types: ['code'],
    }),
)

export async function refreshAccessToken(refresh_token: string) {
  const client = await oidcClient
  return client.grant({ refresh_token, grant_type: 'refresh_token' })
}

function tryExtractCode(location?: string | null): string | null {
  if (!location) return null
  try {
    return new URL(location).searchParams.get('code')
  } catch {
    try {
      const full = location.startsWith('/') ? `${LOGIN_URL}${location}` : location
      return new URL(full).searchParams.get('code')
    } catch {
      return null
    }
  }
}

function extractFormInputs(html: string, formId: string): Record<string, string> {
  const $ = cheerio.load(html)
  const form = $(`#${formId}`)
  if (!form.length) return {}
  const result: Record<string, string> = {}
  form.find('input').each((_, el) => {
    const name = $(el).attr('name')
    if (name) result[name] = ($(el).val() as string) || ''
  })
  return result
}

function extractAlertMessage(html: string): string | null {
  const $ = cheerio.load(html)
  const pane = $('#alert_pane')
  if (pane.length) {
    const text = pane.text().replace(/[\t\n]+/g, ' ').trim()
    if (text) return text
  }
  return null
}

async function followRedirectForCode(
  aclient: ReturnType<typeof wrapper>,
  location: string,
  depth: number,
): Promise<string | null> {
  if (depth >= MAX_REDIRECT_DEPTH) return null
  const resolved = location.startsWith('/') ? `${LOGIN_URL}${location}` : location
  const resp = await aclient.get(resolved, { maxRedirects: 0, validateStatus: () => true })
  const code = tryExtractCode(resp.headers.location)
  if (code) return code
  if (resp.headers.location) {
    return followRedirectForCode(aclient, resp.headers.location, depth + 1)
  }
  if (resp.status === 200 && typeof resp.data === 'string') {
    return handleOkResponse(aclient, resp.data, depth + 1)
  }
  return null
}

async function handleOkResponse(
  aclient: ReturnType<typeof wrapper>,
  respText: string,
  depth: number,
): Promise<string> {
  if (depth >= MAX_REDIRECT_DEPTH) {
    throw new Error('Authentication failed: too many redirects during login flow')
  }

  // Application authorization page (Python SDK handles this, original plugin did not)
  const authInputs = extractFormInputs(respText, 'frmsignin')
  if ('authorized' in authInputs) {
    authInputs['authorized'] = 'yes'
    const authResp = await aclient({
      method: 'POST',
      url: `${LOGIN_URL}/oauth2/code`,
      data: new URLSearchParams(authInputs),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      maxRedirects: 0,
      validateStatus: () => true,
    })
    const code = tryExtractCode(authResp.headers.location)
    if (code) return code
    if (authResp.headers.location) {
      const followed = await followRedirectForCode(aclient, authResp.headers.location, depth + 1)
      if (followed) return followed
    }
    throw new Error('Authentication failed: could not authorize application')
  }

  // MFA enrollment page
  if (respText.includes('Add Multi-Factor Authentication') || respText.includes('addMfaForm')) {
    const $ = cheerio.load(respText)
    const formData: Record<string, string> = {}
    const mfaForm = $('#addMfaForm')
    if (mfaForm.length) {
      mfaForm.find('input').each((_, el) => {
        const name = $(el).attr('name')
        if (name) formData[name] = ($(el).val() as string) || ''
      })
    }
    if (!formData['_csrf']) {
      const csrfMeta = $('meta[name="_csrf"]').attr('content')
      if (csrfMeta) formData['_csrf'] = csrfMeta
    }

    const skipResp = await aclient({
      method: 'POST',
      url: `${LOGIN_URL}/account/active/redirect`,
      data: new URLSearchParams(formData),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      maxRedirects: 0,
      validateStatus: () => true,
    })

    const code = tryExtractCode(skipResp.headers.location)
    if (code) return code
    if (skipResp.headers.location) {
      const followed = await followRedirectForCode(aclient, skipResp.headers.location, depth + 1)
      if (followed) return followed
    }
    if (skipResp.status === 200 && typeof skipResp.data === 'string') {
      return handleOkResponse(aclient, skipResp.data, depth + 1)
    }
    throw new Error('Authentication failed: could not skip MFA enrollment. Please complete MFA setup in the SmartHQ app.')
  }

  // Terms acceptance page
  if (respText.includes('Almost Finished') && respText.includes('/oauth2/terms/accept')) {
    const $ = cheerio.load(respText)
    const formData: Record<string, string> = {}

    let termsForm = $('#termsform')
    if (!termsForm.length) termsForm = $("form[name='termsform']")

    if (termsForm.length) {
      termsForm.find('input').each((_, el) => {
        const name = $(el).attr('name')
        if (name) formData[name] = ($(el).val() as string) || ''
      })
    } else {
      // Fallback: extract fields via regex for malformed HTML
      const sigMatch = respText.match(/name="signature"\s+value="([^"]+)"/)
      if (sigMatch) formData['signature'] = sigMatch[1]
      const lasMatch = respText.match(/name="login_actions_signature"[^>]*value=([^>\s]+)/)
      if (lasMatch) formData['login_actions_signature'] = lasMatch[1].replace(/>$/, '')
      const devMatch = respText.match(/name="isDeveloper"\s+value="([^"]+)"/)
      if (devMatch) formData['isDeveloper'] = devMatch[1]
      const csrfMatch = respText.match(/name="_csrf"\s+value="([^"]+)"/)
      if (csrfMatch) formData['_csrf'] = csrfMatch[1]
    }

    formData['developerTerms'] = 'on'
    formData['connected_terms'] = 'on'

    if (!formData['_csrf']) {
      const csrfMeta = $('meta[name="_csrf"]').attr('content')
      if (csrfMeta) formData['_csrf'] = csrfMeta
    }

    const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
    if (formData['_csrf']) headers['X-CSRF-TOKEN'] = formData['_csrf']

    const termsResp = await aclient({
      method: 'POST',
      url: `${LOGIN_URL}/oauth2/terms/accept`,
      data: new URLSearchParams(formData),
      headers,
      maxRedirects: 0,
      validateStatus: () => true,
    })

    const code = tryExtractCode(termsResp.headers.location)
    if (code) return code
    if (termsResp.headers.location) {
      const followed = await followRedirectForCode(aclient, termsResp.headers.location, depth + 1)
      if (followed) return followed
    }
    if (termsResp.status === 200 && typeof termsResp.data === 'string') {
      return handleOkResponse(aclient, termsResp.data, depth + 1)
    }
    throw new Error('Authentication failed: could not accept terms. Please accept terms in the SmartHQ app.')
  }

  // Check for credential errors from the alert pane
  const alertMsg = extractAlertMessage(respText)
  if (alertMsg) {
    throw new Error(`Authentication failed: ${alertMsg}`)
  }

  throw new Error(
    'Authentication failed: No authorization code received and no known intermediate page detected. '
    + 'Please verify your credentials are correct and try logging into the SmartHQ app first.',
  )
}

export default async function getAccessToken(username: string, password: string) {
  const client = await oidcClient

  const oauthUrl = client.authorizationUrl()

  const jar = new CookieJar()
  const aclient = wrapper(axios.create({ jar, timeout: AUTH_TIMEOUT }))

  const htmlPageResponse = await aclient.get(oauthUrl)

  const page = cheerio.load(htmlPageResponse.data)
  const formEl = page('#frmsignin')
  if (!formEl.length) {
    throw new Error('Authentication failed: login form not found. GE may have changed their login page.')
  }

  const carryInputs = mapValues(
    keyBy(formEl.serializeArray(), o => o.name),
    t => t.value,
  )

  const body = new URLSearchParams({ ...carryInputs, username, password })

  const res = await aclient({
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'origin': 'https://accounts.brillion.geappliances.com',
    },
    url: 'https://accounts.brillion.geappliances.com/oauth2/g_authenticate',
    data: body,
    maxRedirects: 0,
    validateStatus: () => true,
  })

  let code = tryExtractCode(res.headers.location)

  if (!code && res.headers.location) {
    code = await followRedirectForCode(aclient, res.headers.location, 0)
  }

  if (!code && res.status === 200 && typeof res.data === 'string') {
    code = await handleOkResponse(aclient, res.data, 0)
  }

  if (!code) {
    throw new Error('Authentication failed: No authorization code received')
  }

  return client.grant({ grant_type: 'authorization_code', code, redirect_uri: OAUTH2_REDIRECT_URI })
}
