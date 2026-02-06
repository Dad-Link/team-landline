const functions = require('firebase-functions/v2');
const express = require('express');
const admin = require('firebase-admin');
const twilio = require('twilio');

const jwt = require('jsonwebtoken');
const SHOPIFY_BILLING_TEST = (process.env.SHOPIFY_BILLING_TEST || 'true') === 'true';


// Initialize Firebase Admin
if (!admin.apps.length) {
  admin.initializeApp();
}
const db = admin.firestore();
console.log('✅ Firebase connected via Functions - Production');


// **ENVIRONMENT VARIABLES - CLOUD RUN PROCESS.ENV ONLY**
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const UK_BUNDLE_SID = process.env.TWILIO_UK_BUNDLE_SID;
const UK_ADDRESS_SID = process.env.TWILIO_UK_ADDRESS_SID;
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET;
const UK_MOBILE_BUNDLE_SID = process.env.TWILIO_UK_MOBILE_BUNDLE_SID;
console.log('UK Mobile Bundle:', UK_MOBILE_BUNDLE_SID ? `${UK_MOBILE_BUNDLE_SID.substring(0, 15)}...` : 'NOT SET ❌');
console.log('🔍 Environment Variables Check:');
console.log('Twilio SID:', TWILIO_ACCOUNT_SID ? 'Set ✅' : 'Missing ❌');
console.log('Twilio Token:', TWILIO_AUTH_TOKEN ? 'Set ✅' : 'Missing ❌');
console.log('UK Bundle:', UK_BUNDLE_SID ? `${UK_BUNDLE_SID.substring(0, 15)}...` : 'NOT SET ❌');
console.log('UK Address:', UK_ADDRESS_SID ? `${UK_ADDRESS_SID.substring(0, 15)}...` : 'NOT SET ❌');
console.log('Shopify Key:', SHOPIFY_API_KEY ? 'Set ✅' : 'Missing ❌');

// **LAZY TWILIO CLIENT INITIALIZATION**
let twilioClient = null;

const getTwilioClient = () => {
  if (!twilioClient && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
    twilioClient = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);
    console.log('✅ Twilio client initialized');
  }
  
  if (!twilioClient) {
    throw new Error('Twilio credentials not configured. Please set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN environment variables.');
  }
  
  return twilioClient;
};

const crypto = require('crypto');

const validateShopifyWebhook = (req, res, next) => {
  try {
    const hmacHeader = req.get('X-Shopify-Hmac-Sha256');
    const webhookSecret = process.env.SHOPIFY_WEBHOOK_SECRET || SHOPIFY_API_SECRET;

    if (!hmacHeader || !webhookSecret) {
      console.error('⚠️ Webhook validation failed: Missing HMAC or secret');
      return res.status(200).send('ok'); // Always return 200 to Shopify
    }

    // Ensure rawBody exists
    const bodyBuffer = req.rawBody || Buffer.from(req.body ? JSON.stringify(req.body) : '', 'utf8');
    
    if (!bodyBuffer || bodyBuffer.length === 0) {
      console.error('⚠️ Webhook validation failed: Empty body');
      return res.status(200).send('ok');
    }

    const digest = crypto
      .createHmac('sha256', webhookSecret)
      .update(bodyBuffer)
      .digest('base64');

    if (digest !== hmacHeader) {
      console.error('⚠️ Webhook validation failed: Invalid HMAC');
      return res.status(200).send('ok'); // Don't reject, just log
    }
    
    return next();
  } catch (error) {
    console.error('⚠️ Webhook validation error:', error);
    return res.status(200).send('ok'); // Always return 200
  }
};


// ADD near top (below other requires)
const SHOPIFY_API_VERSION = '2025-07';

// Build Shopify install URL
function buildInstallUrl(shop, state, redirectUri, scopes = []) {
  const params = new URLSearchParams({
    client_id: process.env.SHOPIFY_API_KEY,
    scope: scopes.join(','),
    redirect_uri: redirectUri,
    state
  });
  return `https://${shop}/admin/oauth/authorize?${params.toString()}`;
}

// Verify OAuth callback HMAC (hex)
function verifyShopifyOAuthHmac(query) {
  const hmac = query.hmac;
  if (!hmac) return false;
  const queryCopy = { ...query };
  delete queryCopy.hmac;
  delete queryCopy.signature;

  const message = Object.keys(queryCopy)
    .sort()
    .map(k => `${k}=${Array.isArray(queryCopy[k]) ? queryCopy[k].join(',') : queryCopy[k]}`)
    .join('&');

  const digest = require('crypto')
    .createHmac('sha256', process.env.SHOPIFY_API_SECRET)
    .update(message)
    .digest('hex');

  // constant-time compare
  if (digest.length !== hmac.length) return false;
  let result = 0;
  for (let i = 0; i < digest.length; i++) {
    result |= digest.charCodeAt(i) ^ hmac.charCodeAt(i);
  }
  return result === 0;
}

const app = express();

app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Credentials', 'true'); // Add this
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Shop-Domain, X-Shopify-Host');
  
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

app.use(express.json({
  limit: '10mb',
  verify: (req, res, buf) => { req.rawBody = buf; }
}));
app.use(express.urlencoded({ extended: true }));

// REPLACE your requireShopifySession function with this improved version:
function requireShopifySession(req, res, next) {
  const reauth = (reason = 'Invalid/expired token') => {
    const shop = (req.headers['x-shop-domain'] || req.query.shop || req.body?.shop || '').toLowerCase();
    const host = req.query.host || req.headers['x-shopify-host'] || '';
    
    console.warn(`🔒 Auth required: ${reason} | shop: ${shop}`);
    
    res.set('X-Shopify-API-Request-Failure-Reauthorize', '1');
    res.set(
      'X-Shopify-API-Request-Failure-Reauthorize-Url',
      `https://${req.get('host')}/auth?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ''}`
    );
    return res.status(401).json({
      error: reason,
      shop: shop || 'unknown',
      reauth_url: `https://${req.get('host')}/auth?shop=${encodeURIComponent(shop)}`
    });
  };

  try {
    const auth = req.headers.authorization || '';
    const [, token] = auth.split(' ');
    
    if (!token) {
      return reauth('Missing bearer token');
    }

    const secret = process.env.SHOPIFY_API_SECRET;
    const apiKey = process.env.SHOPIFY_API_KEY;
    
    if (!secret || !apiKey) {
      console.error('❌ Missing Shopify credentials');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Verify JWT
    const payload = jwt.verify(token, secret, {
      algorithms: ['HS256'],
      audience: apiKey,
      // Add clock tolerance for timing issues
      clockTolerance: 30
    });

    // Extract shop from dest/iss
    const dest = payload.dest || payload.iss || '';
    const shopFromJwt = (dest.match(/https?:\/\/([^/]+)/)?.[1]) || '';
    
    if (!shopFromJwt) {
      return reauth('Invalid token: missing shop');
    }

    // Attach verified data to request
    req.shopifyJwt = payload;
    req.shopDomain = shopFromJwt;
    
    // Ensure x-shop-domain header is set
    if (!req.headers['x-shop-domain']) {
      req.headers['x-shop-domain'] = shopFromJwt;
    }

    return next();
    
  } catch (e) {
    console.warn('JWT verification failed:', e.message);
    return reauth(`Token verification failed: ${e.message}`);
  }
}
// Skip authentication for ALL webhook routes
app.use('/webhooks', (req, res, next) => {
  console.log(`🔗 Webhook bypass auth: ${req.method} ${req.path}`);
  return next(); // Skip auth for all Shopify webhooks
});

// Protect all /api routes with the Shopify session token,
// but allow Twilio callbacks to skip auth.
app.use('/api', (req, res, next) => {
  const path = req.path.toLowerCase();
  if (
    path === '/voice-webhook' ||
    path === '/sms-webhook' ||
    path === '/recording-status' ||
    path === '/call-complete'
  ) {
    return next(); // skip auth for Twilio webhooks
  }
  return requireShopifySession(req, res, next);
});

// Start one-time add-on purchase
app.post('/api/billing/addon/:code', async (req, res) => {
  try {
    const shop = getShopFromRequest(req);
    const { code } = req.params;
    const hostParam = req.query.host || '';
    
    console.log(`🛒 Addon purchase request: shop=${shop}, code=${code}, host=${hostParam}`);
    
    const spec = ADDON_CATALOG[code];
    if (!shop || shop === 'unknown-shop') {
      console.error('❌ Addon failed: Missing or invalid shop domain');
      return res.status(400).json({ error: 'Shop domain required' });
    }
    if (!spec) {
      console.error(`❌ Addon failed: Invalid add-on code: ${code}`);
      return res.status(400).json({ error: 'Invalid add-on code' });
    }

    console.log(`📋 Addon spec: ${spec.name} - ${spec.price} GBP`);

    const token = await getShopAccessToken(shop);
    console.log(`🔐 Got access token for addon purchase: ${shop.substring(0, 10)}...`);
    
    const returnUrl = `https://${req.get('host')}/auth/billing/callback?shop=${encodeURIComponent(shop)}&host=${encodeURIComponent(hostParam)}&kind=addon&code=${encodeURIComponent(code)}`;
    console.log(`🔄 Addon return URL: ${returnUrl}`);

    const mutation = `
      mutation CreateOneTime($name: String!, $price: MoneyInput!, $returnUrl: URL!) {
        appPurchaseOneTimeCreate(
          name: $name
          price: $price
          returnUrl: $returnUrl
          test: ${SHOPIFY_BILLING_TEST ? 'true' : 'false'}
        ) {
          confirmationUrl
          userErrors { field message }
        }
      }
    `;
    const variables = {
      name: spec.name,
      price: { amount: spec.price, currencyCode: 'GBP' },
      returnUrl
    };
    
    console.log(`🌐 Sending Shopify GraphQL mutation for addon: ${spec.name}`);
    const data = await shopifyGraphQL(shop, token, mutation, variables);
    const result = data.appPurchaseOneTimeCreate;
    
    if (result.userErrors?.length) {
      console.error('❌ Shopify addon errors:', result.userErrors);
      return res.status(400).json({ error: result.userErrors.map(u => u.message).join('; ') });
    }
    if (!result.confirmationUrl) {
      console.error('❌ No confirmationUrl in addon response:', result);
      return res.status(500).json({ error: 'No confirmationUrl returned from Shopify' });
    }
    
    console.log(`✅ Addon purchase created successfully: ${result.confirmationUrl}`);
    res.json({ confirmationUrl: result.confirmationUrl });
  } catch (e) {
    console.error('💥 Addon purchase error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/webhooks/app_subscriptions/update', validateShopifyWebhook, (req, res) => {
  try {
    res.status(200).send('ok'); // ACK immediately

    // Background work
    setImmediate(async () => {
      try {
        const shop = (req.get('X-Shopify-Shop-Domain') || req.body?.shop_domain || '').toLowerCase();
        if (!shop) return;

        const sub = req.body?.app_subscription || req.body || {};
        const statusRaw = sub.status || '';
        const status = String(statusRaw).toLowerCase();
        const shopifySubId = sub.admin_graphql_api_id || sub.id || '';
        const name = String(sub.name || '');

        const PLAN_NAME_TO_KEY = {
          'starter plan': 'starter',
          'business plan': 'business',
          'enterprise plan': 'enterprise'
        };
        const planKey = PLAN_NAME_TO_KEY[name.toLowerCase()] || null;

        // Try to locate the subscription doc by GraphQL/REST ID
        let subDocSnap = null;
        if (shopifySubId) {
          const byIdSnap = await db.collection('subscriptions')
            .where('shopifySubId', '==', shopifySubId)
            .limit(1)
            .get();
          if (!byIdSnap.empty) subDocSnap = byIdSnap.docs[0];
        }

        async function cancelAllActiveForShop() {
          const activeSnap = await db.collection('subscriptions')
            .where('shopDomain', '==', shop)
            .where('status', '==', 'active')
            .get();
          if (activeSnap.empty) return;
          const batch = db.batch();
          activeSnap.forEach(d => {
            batch.update(d.ref, {
              status: 'cancelled',
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              webhookStatus: status
            });
          });
          await batch.commit();
        }

        if (status === 'active') {
          if (subDocSnap) {
            await subDocSnap.ref.set({
              shopDomain: shop,
              plan: planKey || subDocSnap.data()?.plan || 'starter',
              status: 'active',
              shopifySubId,
              name,
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              webhookStatus: status
            }, { merge: true });

            // Ensure only one active
            const othersSnap = await db.collection('subscriptions')
              .where('shopDomain', '==', shop)
              .where('status', '==', 'active')
              .get();
            const batch = db.batch();
            othersSnap.forEach(d => {
              if (d.id !== subDocSnap.id) {
                batch.update(d.ref, {
                  status: 'cancelled',
                  updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                  webhookStatus: status
                });
              }
            });
            await batch.commit();
          } else {
            await cancelAllActiveForShop();
            await db.collection('subscriptions').add({
              shopDomain: shop,
              plan: planKey || 'starter',
              status: 'active',
              shopifySubId: shopifySubId || null,
              name,
              createdAt: admin.firestore.FieldValue.serverTimestamp(),
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              webhookStatus: status
            });
          }
          return;
        }

        // Non-active -> cancel
        if (subDocSnap) {
          await subDocSnap.ref.set({
            status: 'cancelled',
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            webhookStatus: status
          }, { merge: true });
        } else {
          await cancelAllActiveForShop();
        }
      } catch (e) {
        console.error('subs/update background error', e);
      }
    });
  } catch (e) {
    // Still respond 200 to prevent retries
    res.status(200).send('ok');
  }
});
// Helper to fetch a shop's Admin API access token saved during OAuth
async function getShopAccessToken(shop) {
  const doc = await db.collection('shops').doc(shop).get();
  const token = doc.data()?.accessToken;
  if (!token) throw new Error('Shop not installed or missing access token');
  return token;
}

// Minimal GraphQL caller for Shopify Admin API
async function shopifyGraphQL(shop, accessToken, query, variables = {}) {
  const res = await fetch(`https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': accessToken
    },
    body: JSON.stringify({ query, variables })
  });
  const json = await res.json();
  if (!res.ok || json.errors) {
    const msg = json.errors?.[0]?.message || `HTTP ${res.status}`;
    throw new Error(`Shopify GraphQL error: ${msg}`);
  }
  return json.data;
}

// Price table to match your plans
const SHOPIFY_BILLING_PLANS = {
  starter:     { name: 'Starter Plan',     amount: 9.99,  currencyCode: 'GBP', interval: 'EVERY_30_DAYS', trialDays: 0 },
  business:    { name: 'Business Plan',    amount: 19.99, currencyCode: 'GBP', interval: 'EVERY_30_DAYS', trialDays: 0 },
  enterprise:  { name: 'Enterprise Plan',  amount: 39.99, currencyCode: 'GBP', interval: 'EVERY_30_DAYS', trialDays: 0 }
};

// Create a Shopify App Subscription and return confirmationUrl
app.post('/api/billing/subscribe/:plan', async (req, res) => {
  try {
    const shop = getShopFromRequest(req);
    const { plan } = req.params;
    const hostParam = req.query.host || '';
    
    console.log(`💳 Billing subscription request: shop=${shop}, plan=${plan}, host=${hostParam}`);
    
    if (!shop || shop === 'unknown-shop') {
      console.error('❌ Billing failed: Missing or invalid shop domain');
      return res.status(400).json({ error: 'Shop domain required' });
    }
    
    const spec = SHOPIFY_BILLING_PLANS[plan];
    if (!spec) {
      console.error(`❌ Billing failed: Invalid plan: ${plan}`);
      return res.status(400).json({ error: 'Invalid plan' });
    }

    console.log(`📋 Plan spec: ${spec.name} - ${spec.amount} ${spec.currencyCode}`);

    const token = await getShopAccessToken(shop);
    console.log(`🔐 Got access token for shop: ${shop.substring(0, 10)}...`);

    const returnUrl = `https://${req.get('host')}/auth/billing/callback?shop=${encodeURIComponent(shop)}&host=${encodeURIComponent(hostParam)}&plan=${encodeURIComponent(plan)}&kind=sub`;
    console.log(`🔄 Return URL: ${returnUrl}`);

    const mutation = `
      mutation CreateSub($name: String!, $returnUrl: URL!, $lineItems: [AppSubscriptionLineItemInput!]!, $trialDays: Int) {
        appSubscriptionCreate(
          name: $name
          returnUrl: $returnUrl
          test: ${SHOPIFY_BILLING_TEST ? 'true' : 'false'}
          trialDays: $trialDays
          lineItems: $lineItems
        ) {
          confirmationUrl
          appSubscription { id name status }
          userErrors { field message }
        }
      }
    `;

    const variables = {
      name: spec.name,
      returnUrl,
      trialDays: spec.trialDays,
      lineItems: [
        {
          plan: {
            appRecurringPricingDetails: {
              interval: spec.interval,
              price: { amount: spec.amount, currencyCode: spec.currencyCode }
            }
          }
        }
      ]
    };

    console.log(`🌐 Sending Shopify GraphQL mutation for: ${spec.name}`);
    const data = await shopifyGraphQL(shop, token, mutation, variables);
    const result = data.appSubscriptionCreate;
    
    if (result.userErrors?.length) {
      console.error('❌ Shopify billing errors:', result.userErrors);
      return res.status(400).json({ error: result.userErrors.map(u => u.message).join('; ') });
    }
    
    if (!result.confirmationUrl) {
      console.error('❌ No confirmationUrl in Shopify response:', result);
      return res.status(500).json({ error: 'No confirmationUrl returned from Shopify' });
    }

    console.log(`✅ Billing subscription created successfully: ${result.confirmationUrl}`);
    return res.json({ confirmationUrl: result.confirmationUrl });
  } catch (e) {
    console.error('💥 Billing subscribe error:', e);
    return res.status(500).json({ error: e.message });
  }
});

// REPLACE your existing /auth/billing/callback with this:
app.get('/auth/billing/callback', async (req, res) => {
  try {
    const shop = (req.query.shop || '').toLowerCase();
    const host = req.query.host || '';
    const kind = (req.query.kind || 'sub').toLowerCase();
    const plan = req.query.plan || 'starter';
    const code = req.query.code || '';

    console.log(`💳 Billing callback: shop=${shop}, kind=${kind}, plan=${plan}, code=${code}`);

    if (!shop || !shop.endsWith('.myshopify.com')) {
      return res.status(400).send('Missing or invalid shop');
    }

    // Get the access token
    const token = await getShopAccessToken(shop);

    // Handle subscription billing
    if (kind === 'sub') {
      try {
        // Verify the subscription is actually active
        const query = `
          query CurrentAppInstallation {
            currentAppInstallation {
              activeSubscriptions {
                id name status
                lineItems {
                  plan {
                    pricingDetails {
                      __typename
                      ... on AppRecurringPricing {
                        interval
                        price { amount currencyCode }
                      }
                    }
                  }
                }
              }
            }
          }
        `;

        const data = await shopifyGraphQL(shop, token, query);
        const active = data.currentAppInstallation?.activeSubscriptions || [];

        if (active.length > 0) {
          // Success - update our records
          const batch = db.batch();

          // Cancel existing subscriptions
          const existingActive = await db.collection('subscriptions')
            .where('shopDomain', '==', shop)
            .where('status', '==', 'active')
            .get();

          existingActive.forEach(doc => batch.update(doc.ref, {
            status: 'cancelled',
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
          }));

          // Create new subscription
          const newSubRef = db.collection('subscriptions').doc();
          batch.set(newSubRef, {
            shopDomain: shop,
            plan: plan,
            status: 'active',
            shopifySubId: active[0].id,
            name: active[0].name,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
          });

          await batch.commit();
          console.log(`✅ Subscription activated: ${plan} for ${shop}`);
        }
      } catch (e) {
        console.warn('Subscription verification failed:', e.message);
      }
    }

    // Handle add-on billing
    if (kind === 'addon') {
      try {
        const spec = ADDON_CATALOG[code];
        if (spec) {
          const cycle = getCycleInfo();
          await db.collection('addons').add({
            shopDomain: shop,
            code: spec.code,
            type: spec.type,
            units: spec.units,
            price: spec.price,
            status: 'active',
            cycle: cycle.key,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
          });
          console.log(`✅ Add-on activated: ${code} for ${shop}`);
        }
      } catch (e) {
        console.warn('Add-on activation failed:', e.message);
      }
    }

    // CRITICAL FIX: Always redirect back to embedded app with proper parameters
    const redirectUrl = `/?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ''}`;
    
    // Add success message in URL for user feedback
    const successParam = kind === 'addon' ? '&addon_success=1' : '&billing_success=1';
    
    return res.redirect(redirectUrl + successParam);

  } catch (e) {
    console.error('💥 Billing callback error:', e);
    const shop = req.query.shop || '';
    const host = req.query.host || '';
    // Still redirect back to avoid 404, but with error flag
    const redirectUrl = `/?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ''}&billing_error=1`;
    return res.redirect(redirectUrl);
  }
});

const BILLING_PLANS = {
  starter: {
    name: 'Starter Plan',
    price: 9.99,
    features: { minutesIncluded: 500, overageRate: 0.05, maxNumbers: 1, smsIncluded: 150 } // Changed from 500 to 150
  },
  business: {
    name: 'Business Plan',
    price: 19.99,
    features: { minutesIncluded: 2000, overageRate: 0.03, maxNumbers: 3, smsIncluded: 350 } // Changed from 1500 to 350
  },
  enterprise: {
    name: 'Enterprise Plan',
    price: 39.99,
    features: { minutesIncluded: -1, overageRate: 0, maxNumbers: 10, smsIncluded: 800 } // Changed from -1 to 800
  }
};

// 2) Add an add-on catalog (SMS and Minutes)
// Updated competitive add-on catalog matching frontend
const ADDON_CATALOG = {
  // SMS Add-ons (competitive pricing)
  'sms-200':  { code: 'sms-200',  type: 'sms', units: 200,  price: 14.99, name: 'SMS Boost 200' },
  'sms-400':  { code: 'sms-400',  type: 'sms', units: 400,  price: 26.99, name: 'SMS Plus 400' },
  'sms-800':  { code: 'sms-800',  type: 'sms', units: 800,  price: 48.99, name: 'SMS Pro 800' },
  'sms-1500': { code: 'sms-1500', type: 'sms', units: 1500, price: 89.99, name: 'SMS Max 1500' },
  'sms-3000': { code: 'sms-3000', type: 'sms', units: 3000, price: 164.99, name: 'SMS Unlimited 3000' },
  
  // Voice Minutes Add-ons
  'minutes-500':  { code: 'minutes-500',  type: 'minutes', units: 500,  price: 19.99, name: 'Minutes 500' },
  'minutes-1000': { code: 'minutes-1000', type: 'minutes', units: 1000, price: 34.99, name: 'Minutes 1000' },
  'minutes-2000': { code: 'minutes-2000', type: 'minutes', units: 2000, price: 64.99, name: 'Minutes 2000' }
};


function getCycleInfo(date = new Date()) {
  const y = date.getUTCFullYear();
  const m = date.getUTCMonth(); // 0-based
  const start = new Date(Date.UTC(y, m, 1, 0, 0, 0));
  const end = new Date(Date.UTC(y, m + 1, 1, 0, 0, 0)); // exclusive
  return {
    key: `${y}-${String(m + 1).padStart(2, '0')}`, // e.g., 2025-08
    startTs: admin.firestore.Timestamp.fromDate(start),
    endTs: admin.firestore.Timestamp.fromDate(end)
  };
}
async function getActivePlanFeatures(shopDomain) {
  const snap = await db.collection('subscriptions')
    .where('shopDomain', '==', shopDomain)
    .where('status', '==', 'active')
    .limit(1)
    .get();
  if (snap.empty) {
    return { minutesIncluded: 0, smsIncluded: 0, maxNumbers: 0, overageRate: 0.10 };
  }
  const plan = snap.docs[0].data().plan;
  return BILLING_PLANS[plan]?.features || { minutesIncluded: 0, smsIncluded: 0, maxNumbers: 0, overageRate: 0.10 };
}

async function sumAddons(shopDomain, type, cycleKey) {
  const q = await db.collection('addons')
    .where('shopDomain', '==', shopDomain)
    .where('type', '==', type)           // 'sms' | 'minutes'
    .where('status', '==', 'active')
    .where('cycle', '==', cycleKey)      // monthly cycle
    .get();
  return q.docs.reduce((sum, d) => sum + (d.data().units || 0), 0);
}

async function getSmsUsedThisCycle(shopDomain, cycleInfo) {
  const snap = await db.collection('sms-history')
    .where('shopDomain', '==', shopDomain)
    .where('type', '==', 'outbound')
    .where('timestamp', '>=', cycleInfo.startTs)
    .where('timestamp', '<', cycleInfo.endTs)
    .get();
  return snap.size; // one doc per sent message
}

async function getMinutesUsedThisCycle(shopDomain, cycleInfo) {
  const snap = await db.collection('call-history')
    .where('shopDomain', '==', shopDomain)
    .where('timestamp', '>=', cycleInfo.startTs)
    .where('timestamp', '<', cycleInfo.endTs)
    .get();
  // Sum durations (seconds) -> minutes
  const totalSeconds = snap.docs.reduce((sum, d) => sum + (parseInt(d.data().duration) || 0), 0);
  return Math.ceil(totalSeconds / 60);
}

// **PRODUCTION SHOP DOMAIN HANDLER - NO MORE MOCK**
const getShopFromRequest = (req) => {
  const shop = req.query.shop || req.body.shop || req.headers['x-shop-domain'];
  
  if (!shop) {
    console.log('⚠️ No shop domain provided in request');
    console.log('Query params:', JSON.stringify(req.query));
    console.log('Body shop:', req.body?.shop);
    console.log('Headers shop:', req.headers['x-shop-domain']);
  }
  
  return shop || 'unknown-shop';
};


app.get('/api/usage', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    if (!shopDomain || shopDomain === 'unknown-shop') return res.status(400).json({ error: 'Shop domain required' });

    const cycle = getCycleInfo();
    const features = await getActivePlanFeatures(shopDomain);

    // SMS
    const smsPlan = features.smsIncluded ?? 0;
    const smsAddons = await sumAddons(shopDomain, 'sms', cycle.key);
    const smsAllowance = smsPlan < 0 ? -1 : smsPlan + smsAddons; // -1 means unlimited
    const smsUsed = await getSmsUsedThisCycle(shopDomain, cycle);
    const smsRemaining = smsAllowance < 0 ? -1 : Math.max(0, smsAllowance - smsUsed);

    // Minutes
    const minPlan = features.minutesIncluded ?? 0;
    const minAddons = await sumAddons(shopDomain, 'minutes', cycle.key);
    const minutesAllowance = minPlan < 0 ? -1 : minPlan + minAddons;
    const minutesUsed = await getMinutesUsedThisCycle(shopDomain, cycle);
    const minutesRemaining = minutesAllowance < 0 ? -1 : Math.max(0, minutesAllowance - minutesUsed);

    res.json({
      cycle: cycle.key,
      sms: { allowance: smsAllowance, used: smsUsed, remaining: smsRemaining, addons: smsAddons, planIncluded: smsPlan },
      minutes: { allowance: minutesAllowance, used: minutesUsed, remaining: minutesRemaining, addons: minAddons, planIncluded: minPlan },
      timestamp: new Date().toISOString()
    });
  } catch (e) {
    console.error('usage error', e);
    res.status(500).json({ error: 'Failed to compute usage: ' + e.message });
  }
});

// **API: SMS History** - ADD THIS MISSING ENDPOINT
app.get('/api/sms-history', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    console.log(`💬 Fetching SMS history for shop: ${shopDomain}`);
    
    if (shopDomain === 'unknown-shop') {
      return res.status(400).json({
        error: 'Shop domain required',
        message: 'Please provide shop parameter in URL'
      });
    }
    
    const smsRef = db.collection('sms-history')
      .where('shopDomain', '==', shopDomain)
      .orderBy('timestamp', 'desc')
      .limit(100);
    
    const snapshot = await smsRef.get();
    
    const messages = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      timestamp: doc.data().timestamp?.toDate?.()?.toISOString?.() || new Date().toISOString()
    }));

    console.log(`💬 Found ${messages.length} SMS messages for ${shopDomain}`);
    res.json(messages);
    
  } catch (error) {
    console.error('❌ Error fetching SMS history:', error);
    res.status(500).json({ error: 'Failed to fetch SMS history: ' + error.message });
  }
});

// 5) New: POST /api/addons/purchase -> activate an add-on for this month
// Body: { shop, code: 'sms-1000' | 'sms-5000' | 'minutes-1000' | 'minutes-5000' }
app.post('/api/addons/purchase', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    const { code } = req.body || {};
    if (!shopDomain || shopDomain === 'unknown-shop') return res.status(400).json({ error: 'Shop domain required' });
    const spec = ADDON_CATALOG[code];
    if (!spec) return res.status(400).json({ error: 'Invalid add-on code' });

    const cycle = getCycleInfo();
    await db.collection('addons').add({
      shopDomain,
      code: spec.code,
      type: spec.type,          // 'sms' | 'minutes'
      units: spec.units,        // integer
      price: spec.price,        // informational
      status: 'active',
      cycle: cycle.key,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

      res.json({ success: true, message: `Activated add-on ${spec.name} for ${cycle.key}`, code: spec.code, name: spec.name, cycle: cycle.key, units: spec.units });
  } catch (e) {
    console.error('purchase addon error', e);
    res.status(500).json({ error: 'Failed to purchase add-on: ' + e.message });
  }
});


// **ROOT ENDPOINT**
app.get('/', (req, res) => {
  res.json({
    message: '🚀 Team Landline API - LIVE PRODUCTION!',
    timestamp: new Date().toISOString(),
    platform: 'Firebase Functions (Node 20)',
    version: '3.0.0',
    status: 'LIVE',
    endpoints: [
      'GET /test',
      'GET /api/available-numbers',
      'GET /api/subscription',
      'POST /api/subscribe/:plan',
      'POST /api/numbers',
      'GET /api/my-numbers',
      'PATCH /api/numbers/:id',
      'GET /api/call-history',
      'POST /api/voice-webhook',
      'POST /api/sms-webhook',
      'GET /api/bundle-diagnostics',
      'GET /api/debug/all-data (temporary)'
    ]
  });
});

// **TEST ENDPOINT**
app.get('/test', (req, res) => {
  res.json({
    success: true,
    message: '🎉 Team Landline - LIVE PRODUCTION READY!',
    timestamp: new Date().toISOString(),
    platform: 'Firebase Functions (Node 20)',
    environment: {
      twilioConfigured: !!(TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN),
      ukBundleConfigured: !!UK_BUNDLE_SID,
      ukAddressConfigured: !!UK_ADDRESS_SID,
      shopifyConfigured: !!(SHOPIFY_API_KEY && SHOPIFY_API_SECRET)
    },
    ukBundle: UK_BUNDLE_SID ? 'Configured ✅' : 'Missing ❌',
    ukAddress: UK_ADDRESS_SID ? 'Configured ✅' : 'Missing ❌',
    support: 'support@team-connect.co.uk'
  });
});

// **API: Available Numbers**
app.get('/api/available-numbers', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { area, limit = 50, country = 'GB' } = req.query;
    
    console.log(`🔍 Fetching ${country} numbers (limit: ${limit})`);
    
    const searchOptions = {
      areaCode: area || undefined,
      limit: Math.min(parseInt(limit), 100)
    };

    let numbers;
    if (country === 'GB') {
      numbers = await client.availablePhoneNumbers('GB').local.list(searchOptions);
    } else {
      numbers = await client.availablePhoneNumbers(country).local.list(searchOptions);
    }

    console.log(`📞 Found ${numbers.length} available numbers`);

    const formattedNumbers = numbers.map((number, index) => {
      const phoneNumber = number.phoneNumber;
      const locality = number.locality || (country === 'GB' ? 'UK' : 'Local');
      
      let price, priceText, tier;
      
      if (country === 'GB') {
        if (phoneNumber.includes('+44 20') || locality.toLowerCase().includes('london')) {
          price = 19.99; priceText = '£19.99/month'; tier = 'business';
        } else {
          price = 9.99; priceText = '£9.99/month'; tier = 'starter';
        }
      } else {
        price = 1.99; priceText = '$1.99/month'; tier = 'starter';
      }

      return {
        id: `twilio_${index}`,
        number: phoneNumber,
        area: locality,
        price: price,
        priceText: priceText,
        tier: tier,
        type: 'Geographic',
        capabilities: number.capabilities,
        available: true,
        country: country,
        timestamp: new Date().toISOString()
      };
    });

    res.json(formattedNumbers);
    
  } catch (error) {
    console.error('❌ Error fetching available numbers:', error);
    res.status(500).json({
      error: 'Failed to fetch available numbers: ' + error.message,
      timestamp: new Date().toISOString()
    });
  }
});
// 4) Add a CSV export endpoint for contacts (place near your other contacts endpoints)
app.get('/api/contacts/export', async (req, res) => {
  try {
    const shopDomain = req.query.shop || req.body?.shop || req.headers['x-shop-domain'];
    if (!shopDomain) return res.status(400).send('Shop domain required');

    const snap = await db.collection('contacts')
      .where('shopDomain', '==', shopDomain)
      .limit(50000) // large export cap
      .get();

    const rows = snap.docs.map(d => d.data());

    // CSV headers aligned with your import: Name,Phone,Tags,Consent
    const header = ['Name','Phone','Tags','Consent'];
    const lines = [header.join(',')];

    for (const r of rows) {
      const Name = (r.name || '').toString();
      const Phone = (r.phone || '').toString();
      const Tags = (r.tags || '').toString();
      const Consent = (r.consent === true) ? 'true' : 'false';
      const escaped = [Name, Phone, Tags, Consent].map(csvEscape);
      lines.push(escaped.join(','));
    }

    const csv = lines.join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="contacts-${new Date().toISOString().slice(0,10)}.csv"`);
    res.send(csv);
  } catch (e) {
    console.error('contacts/export error', e);
    res.status(500).send('Failed to export contacts: ' + e.message);
  }
});

function csvEscape(val) {
  const s = (val ?? '').toString();
  if (s.includes('"') || s.includes(',') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}


// OAuth start: /auth?shop={shop}&host={host}
app.get('/auth', async (req, res) => {
  try {
    const shop = (req.query.shop || '').toLowerCase();
    const host = req.query.host || '';
    if (!shop || !shop.endsWith('.myshopify.com')) {
      return res.status(400).send('Missing or invalid shop');
    }
    // create state and store briefly
    const state = require('crypto').randomBytes(16).toString('hex');
    await db.collection('oauth_states').doc(state).set({
      shop, host, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const redirectUri = `https://${req.get('host')}/auth/callback`;
    // No scopes needed for your current features; keep [] or add scopes later
    const installUrl = buildInstallUrl(shop, state, redirectUri, []);
    return res.redirect(installUrl);
  } catch (e) {
    console.error('auth start error', e);
    return res.status(500).send('Auth error');
  }
});

// OAuth callback
app.get('/auth/callback', async (req, res) => {
  try {
    const { shop, host, code, state } = req.query;
    if (!shop || !code || !state) return res.status(400).send('Missing parameters');

    // Validate HMAC
    if (!verifyShopifyOAuthHmac(req.query)) {
      return res.status(401).send('Invalid HMAC');
    }

    // Validate state
    const stateDoc = await db.collection('oauth_states').doc(String(state)).get();
    if (!stateDoc.exists) {
      return res.status(400).send('Invalid state');
    }
    const stateData = stateDoc.data() || {};
    if (stateData.shop !== shop) {
      return res.status(400).send('State/shop mismatch');
    }
    // Clean up state
    await db.collection('oauth_states').doc(String(state)).delete().catch(() => {});

    // Exchange code for access token
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code
      })
    });
    if (!tokenRes.ok) {
      const t = await tokenRes.text();
      console.error('token exchange failed', tokenRes.status, t);
      return res.status(401).send('Token exchange failed');
    }
    const tokenJson = await tokenRes.json();
    const accessToken = tokenJson.access_token;

    // Store shop installation
    await db.collection('shops').doc(shop).set({
      shop,
      accessToken,
      installedAt: admin.firestore.FieldValue.serverTimestamp(),
      apiVersion: SHOPIFY_API_VERSION
    }, { merge: true });

    // Register app/uninstalled webhook for this shop
    try {
      const webhookRes = await fetch(`https://${shop}/admin/api/${SHOPIFY_API_VERSION}/webhooks.json`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': accessToken
        },
        body: JSON.stringify({
          webhook: {
            topic: 'app/uninstalled',
            address: `https://${req.get('host')}/webhooks/app/uninstalled`,
            format: 'json'
          }
        })
      });
      if (!webhookRes.ok) {
        const wt = await webhookRes.text();
        console.warn('app/uninstalled subscribe failed', webhookRes.status, wt);
      }
    } catch (e) {
      console.warn('webhook register error', e.message);
    }

    // Redirect merchant into your embedded app
    const redirectTarget = `/?shop=${encodeURIComponent(shop)}${host ? `&host=${encodeURIComponent(host)}` : ''}`;
    return res.redirect(redirectTarget);
  } catch (e) {
    console.error('auth callback error', e);
    return res.status(500).send('Auth callback error');
  }
});

if (process.env.ENABLE_DEBUG === 'true') {
  app.get('/api/debug/all-data', async (req, res) => {
    try {
      const shopDomain = req.query.shop || req.headers['x-shop-domain'] || 'unknown';
      const allNumbers = await db.collection('purchased-numbers').get();
      const numbersData = allNumbers.docs.map(doc => ({
        id: doc.id,
        shopDomain: doc.data().shopDomain,
        number: doc.data().number,
        status: doc.data().status
      }));
      const allSubs = await db.collection('subscriptions').get();
      const subsData = allSubs.docs.map(doc => ({
        id: doc.id,
        shopDomain: doc.data().shopDomain,
        plan: doc.data().plan,
        status: doc.data().status
      }));
      res.json({
        currentShop: shopDomain,
        totalNumbers: numbersData.length,
        totalSubs: subsData.length,
        allNumbers: numbersData,
        allSubs: subsData,
        message: 'DEBUG ONLY'
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
}
// **API: Subscription Check**
app.get('/api/subscription', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    console.log('🔍 Checking subscription for:', shopDomain);

    if (shopDomain === 'unknown-shop') {
      return res.status(400).json({
        error: 'Shop domain required',
        message: 'Please provide shop parameter in URL or request body'
      });
    }

    let hasSubscription = false;
    let currentPlan = 'free';
    let features = { minutesIncluded: 0, maxNumbers: 0, overageRate: 0.10 };

    const subscriptionRef = db.collection('subscriptions')
      .where('shopDomain', '==', shopDomain)
      .where('status', '==', 'active');
    
    const snapshot = await subscriptionRef.get();
    
    if (!snapshot.empty) {
      const subscription = snapshot.docs[0].data();
      hasSubscription = true;
      currentPlan = subscription.plan;
      features = BILLING_PLANS[currentPlan]?.features || features;
      console.log('💳 Active subscription found:', currentPlan);
    }

    res.json({
      currentPlan,
      features,
      hasActiveSubscription: hasSubscription,
      shop: shopDomain,
      timestamp: new Date().toISOString(),
      message: hasSubscription ? 'Active subscription found' : 'No active subscription'
    });

  } catch (error) {
    console.error('❌ Subscription check error:', error);
    res.status(500).json({ error: 'Failed to check subscription: ' + error.message });
  }
});

// **API: Subscribe**
app.post('/api/subscribe/:plan', async (req, res) => {
  try {
    const { plan } = req.params;
    const shopDomain = getShopFromRequest(req);
    
    console.log(`💳 Creating ${plan} subscription for ${shopDomain}`);

    if (shopDomain === 'unknown-shop') {
      return res.status(400).json({
        error: 'Shop domain required',
        message: 'Please provide shop parameter in URL or request body'
      });
    }

    if (!BILLING_PLANS[plan]) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    // Cancel existing subscriptions
    const existingSubs = await db.collection('subscriptions')
      .where('shopDomain', '==', shopDomain)
      .get();
    
    const batch = db.batch();
    existingSubs.forEach(doc => {
      batch.update(doc.ref, { status: 'cancelled' });
    });

    // Create new subscription
    const newSubRef = db.collection('subscriptions').doc();
    batch.set(newSubRef, {
      shopDomain: shopDomain,
      plan: plan,
      status: 'active',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      timestamp: new Date().toISOString()
    });

    await batch.commit();
    console.log('✅ Subscription created successfully');

    res.json({
      success: true,
      message: `Successfully subscribed to ${plan} plan! 🎉`,
      plan: plan,
      features: BILLING_PLANS[plan].features,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Subscription creation error:', error);
    res.status(500).json({ error: 'Failed to create subscription: ' + error.message });
  }
});

// **API: Purchase Number**
app.post('/api/numbers', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { number, area, price, tier } = req.body;
    const shopDomain = getShopFromRequest(req);
    
    console.log(`🛒 Purchase request for ${number} | ${shopDomain}`);

    if (shopDomain === 'unknown-shop') {
      return res.status(400).json({
        error: 'Shop domain required',
        message: 'Please provide shop parameter in request body'
      });
    }

    // Check subscription
    const subscriptionRef = db.collection('subscriptions')
      .where('shopDomain', '==', shopDomain)
      .where('status', '==', 'active');
    
    const snapshot = await subscriptionRef.get();
    
    if (snapshot.empty) {
      return res.status(402).json({
        error: 'Subscription required',
        message: 'Please subscribe to a plan to rent phone numbers'
      });
    }

    const subscription = snapshot.docs[0].data();
    const currentNumbers = await db.collection('purchased-numbers')
      .where('shopDomain', '==', shopDomain)
      .where('status', '==', 'active')
      .get();

    const maxNumbers = BILLING_PLANS[subscription.plan]?.features.maxNumbers || 1;
    
    if (currentNumbers.size >= maxNumbers) {
      return res.status(402).json({
        error: 'Plan limit reached',
        message: `Your ${subscription.plan} plan allows ${maxNumbers} numbers. Upgrade to rent more.`
      });
    }

    const isUKNumber = number.startsWith('+44');
    
    // Get the function URL dynamically
    const functionUrl = req.get('host');
    const functionBaseUrl = `https://${functionUrl}`;
    
    const basePurchaseOptions = {
      phoneNumber: number,
      voiceUrl: `${functionBaseUrl}/api/voice-webhook`,
      voiceMethod: 'POST',
      smsUrl: `${functionBaseUrl}/api/sms-webhook`,
      smsMethod: 'POST'
    };

    let purchasedNumber;
    let bundleUsed = false;
    let purchaseStrategy = 'basic';

    const requestedType = (req.body.type || (isUKNumber ? 'geographic' : 'local')).toString().toLowerCase();

    if (isUKNumber) {
      if (requestedType === 'sms' || requestedType === 'mobile') {
        // UK MOBILE (SMS) — Use MOBILE bundle (CORRECTED)
        const mobileOptions = { ...basePurchaseOptions };
        
        if (UK_MOBILE_BUNDLE_SID && UK_ADDRESS_SID) {
          mobileOptions.bundleSid = UK_MOBILE_BUNDLE_SID;  // ✅ CORRECT: Mobile bundle
          mobileOptions.addressSid = UK_ADDRESS_SID;
          bundleUsed = true;
          purchaseStrategy = 'uk_mobile_bundle_address';
          console.log('🇬🇧 Purchasing UK mobile with MOBILE bundle + address');
        } else if (UK_MOBILE_BUNDLE_SID) {
          mobileOptions.bundleSid = UK_MOBILE_BUNDLE_SID;  // ✅ Mobile bundle only
          bundleUsed = true;
          purchaseStrategy = 'uk_mobile_bundle_only';
          console.log('🇬🇧 Purchasing UK mobile with MOBILE bundle only (no address)');
        } else {
          purchaseStrategy = 'uk_mobile_basic';
          console.log('🇬🇧 Purchasing UK mobile WITHOUT bundle (no mobile bundle configured)');
        }

        try {
          purchasedNumber = await client.incomingPhoneNumbers.create(mobileOptions);
          console.log('✅ UK mobile number purchased successfully');
        } catch (mobileError) {
          console.error('❌ UK mobile purchase error:', mobileError);
          throw new Error(`UK mobile number purchase failed: ${mobileError.message}`);
        }

      } else {
        // UK GEOGRAPHIC/LANDLINE — Use GEOGRAPHIC bundle
        if (!UK_BUNDLE_SID || !UK_ADDRESS_SID) {
          throw new Error('UK geographic numbers require a regulatory bundle and address. Please set TWILIO_UK_BUNDLE_SID and TWILIO_UK_ADDRESS_SID.');
        }
        
        const ukGeoOptions = {
          ...basePurchaseOptions,
          bundleSid: UK_BUNDLE_SID,      // ✅ CORRECT: Geographic bundle
          addressSid: UK_ADDRESS_SID
        };
        
        try {
          purchasedNumber = await client.incomingPhoneNumbers.create(ukGeoOptions);
          bundleUsed = true;
          purchaseStrategy = 'uk_geo_bundle_address';
          console.log('✅ UK geographic number purchased with regulatory compliance');
        } catch (ukError) {
          console.error('❌ UK geographic purchase error:', ukError);
          throw new Error(`UK regulatory purchase failed: ${ukError.message}. Bundle or address may need verification.`);
        }
      }
    } else {
      // Non-UK numbers (no bundle)
      try {
        purchasedNumber = await client.incomingPhoneNumbers.create(basePurchaseOptions);
        purchaseStrategy = 'international';
        console.log('🌍 International number purchased');
      } catch (intlError) {
        console.error('❌ International purchase error:', intlError);
        throw new Error(`International number purchase failed: ${intlError.message}`);
      }
    }

    // Enhanced number document with better bundle tracking
    const numberDoc = {
      twilioSid: purchasedNumber.sid,
      number,
      area,
      price,
      tier,
      type: requestedType,
      shopDomain,
      status: 'active',
      forwardTo: '',
      purchaseDate: admin.firestore.FieldValue.serverTimestamp(),
      minutesUsed: 0,
      minutesIncluded: tier === 'starter' ? 500 : tier === 'business' ? 2000 : -1,
      plan: tier,
      country: isUKNumber ? 'GB' : 'US',
      bundleUsed,
      // ✅ ENHANCED: Correct bundle assignment
      bundleSid: bundleUsed ?
        (requestedType === 'sms' || requestedType === 'mobile' ? UK_MOBILE_BUNDLE_SID : UK_BUNDLE_SID) : null,
      addressSid: bundleUsed ? UK_ADDRESS_SID : null,
      purchaseStrategy,
      timestamp: new Date().toISOString(),
      platform: 'Firebase Functions',
      // ✅ NEW: Additional tracking
      purchaseTimestamp: admin.firestore.FieldValue.serverTimestamp(),
      regulatoryCompliant: isUKNumber && bundleUsed,
      errorLog: null
    };

    await db.collection('purchased-numbers').add(numberDoc);
    console.log('✅ Number stored in Firebase with correct bundle tracking');

    res.json({
      success: true,
      message: `📞 Number ${number} rented successfully! ${isUKNumber && requestedType === 'sms' ? 'SMS campaigns ready.' : 'Set up call forwarding in My Numbers.'}`,
      twilioSid: purchasedNumber.sid,
      country: isUKNumber ? 'GB' : 'US',
      bundleUsed: bundleUsed,
      purchaseStrategy: purchaseStrategy,
      regulatoryCompliant: isUKNumber && bundleUsed,
      numberType: requestedType,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Error purchasing number:', error);
    
    // Enhanced error logging
    try {
      await db.collection('purchase-errors').add({
        shopDomain,
        number,
        requestedType,
        error: error.message,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        bundles: {
          ukBundle: UK_BUNDLE_SID ? 'configured' : 'missing',
          ukMobileBundle: UK_MOBILE_BUNDLE_SID ? 'configured' : 'missing',
          ukAddress: UK_ADDRESS_SID ? 'configured' : 'missing'
        }
      });
    } catch (logError) {
      console.error('Failed to log purchase error:', logError);
    }

    res.status(500).json({
      success: false,
      error: 'Failed to purchase number: ' + error.message,
      timestamp: new Date().toISOString(),
      supportInfo: 'If this error persists, check your Twilio regulatory bundles configuration.'
    });
  }
});

// ========================================
// **SHOPIFY GDPR COMPLIANCE WEBHOOKS**
// Add these AFTER your existing endpoints
// ========================================
// 2) Replace validateShopifyWebhook with this raw-body version

// Replace your current /webhooks/app/uninstalled handler with this "soft uninstall"
app.post('/webhooks/app/uninstalled', validateShopifyWebhook, async (req, res) => {
  try {
    const shop = req.get('X-Shopify-Shop-Domain') || req.body?.myshopify_domain || req.body?.shop;
    console.log(`🧹 App uninstalled (soft): ${shop}`);

    // Optional: mark shop as uninstalled, pause automations, etc.
    await db.collection('shops').doc(shop).set({
      status: 'uninstalled',
      uninstalledAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    // Do NOT delete data here; wait for shop/redact to wipe permanently
    res.status(200).send('ok');
  } catch (e) {
    console.error('uninstalled webhook error', e);
    res.status(200).send('ok');
  }
});

// 2) GDPR customers/data_request — ack immediately, then process
app.post('/webhooks/customers/data_request', validateShopifyWebhook, (req, res) => {
  try {
    res.status(200).send('ok'); // ACK immediately

    setImmediate(async () => {
      try {
        const { shop_domain, customer } = req.body;
        const customerId = customer?.id;
        const customerEmail = customer?.email;
        const customerPhone = customer?.phone;

        console.log(`🔐 GDPR Data Request | Shop: ${shop_domain} | Customer: ${customerId}`);

        await db.collection('gdpr-audit').add({
          type: 'data_request',
          shopDomain: shop_domain,
          customerId,
          customerEmail,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          status: 'processing',
          platform: 'Firebase Functions'
        });

        const customerData = {
          request_id: `data_req_${Date.now()}`,
          shop_domain,
          customer,
          requested_at: new Date().toISOString(),
          data: {}
        };

        if (customerPhone || customerEmail) {
          const numbersSnapshot = await db.collection('purchased-numbers')
            .where('shopDomain', '==', shop_domain).get();
          customerData.data.purchased_numbers = numbersSnapshot.docs
            .filter(doc => {
              const d = doc.data();
              return d.customerEmail === customerEmail ||
                     d.customerPhone === customerPhone ||
                     d.forwardTo === customerPhone;
            })
            .map(doc => ({
              id: doc.id,
              number: doc.data().number,
              forwardTo: doc.data().forwardTo,
              purchaseDate: doc.data().purchaseDate?.toDate?.()?.toISOString?.()
            }));
        }

        if (customerPhone) {
          const callsSnapshot = await db.collection('call-history')
            .where('shopDomain', '==', shop_domain).get();
          customerData.data.call_history = callsSnapshot.docs
            .filter(doc => {
              const d = doc.data();
              return d.from === customerPhone || d.to === customerPhone;
            })
            .map(doc => ({
              id: doc.id,
              from: doc.data().from,
              to: doc.data().to,
              timestamp: doc.data().timestamp?.toDate?.()?.toISOString?.(),
              duration: doc.data().duration
            }));
        }

        if (customerPhone) {
          const smsSnapshot = await db.collection('sms-history')
            .where('shopDomain', '==', shop_domain).get();
          customerData.data.sms_history = smsSnapshot.docs
            .filter(doc => {
              const d = doc.data();
              return d.from === customerPhone || d.to === customerPhone;
            })
            .map(doc => ({
              id: doc.id,
              from: doc.data().from,
              to: doc.data().to,
              body: doc.data().body,
              timestamp: doc.data().timestamp?.toDate?.()?.toISOString?.()
            }));
        }

        console.log(`✅ GDPR Data Request processed for ${shop_domain}`);
      } catch (error) {
        console.error('GDPR data_request background error', error);
      }
    });
  } catch (e) {
    res.status(200).send('ok');
  }
});
// Replace your existing /api/send-sms with this version
app.post('/api/send-sms', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { shop, from, message, recipients } = req.body;

    if (!shop || !from || !message || !Array.isArray(recipients) || recipients.length === 0) {
      return res.status(400).json({ error: 'shop, from, message, and recipients[] are required' });
    }

    // Validate "from" belongs to this shop
    const senderSnap = await db.collection('purchased-numbers')
      .where('shopDomain', '==', shop)
      .where('number', '==', from)
      .limit(1)
      .get();
    if (senderSnap.empty) return res.status(403).json({ error: 'Sender number not found for this shop' });

    // Compute monthly cycle (UTC)
    const now = new Date();
    const cycleKey = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    const startOfMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0));
    const startTs = admin.firestore.Timestamp.fromDate(startOfMonth);
    const startOfNextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0));
    const endTs = admin.firestore.Timestamp.fromDate(startOfNextMonth);

    // Get active plan to determine included SMS
    const subSnap = await db.collection('subscriptions')
      .where('shopDomain', '==', shop)
      .where('status', '==', 'active')
      .limit(1)
      .get();

    let planIncluded = 0; // default if no sub
    if (!subSnap.empty) {
      const plan = subSnap.docs[0].data().plan;
      planIncluded = (BILLING_PLANS[plan]?.features?.smsIncluded ?? 0); // -1 means unlimited
    }

    // Sum any active SMS add-ons for this cycle (optional; safe if collection doesn't exist)
    let addonUnits = 0;
    try {
      const addonSnap = await db.collection('addons')
        .where('shopDomain', '==', shop)
        .where('type', '==', 'sms')          // 'sms' add-ons only
        .where('status', '==', 'active')
        .where('cycle', '==', cycleKey)      // e.g. "2025-08"
        .get();
      addonUnits = addonSnap.docs.reduce((sum, d) => sum + (d.data().units || 0), 0);
    } catch (_) {
      // ignore if collection/index not present; treated as 0 add-ons
    }

    const allowance = planIncluded < 0 ? -1 : (planIncluded + addonUnits); // -1 = unlimited

    // Count outbound SMS used this cycle
    const usedSnap = await db.collection('sms-history')
      .where('shopDomain', '==', shop)
      .where('type', '==', 'outbound')
      .where('timestamp', '>=', startTs)
      .where('timestamp', '<', endTs)
      .get();
    const used = usedSnap.size;

    const requested = recipients.length;
    const remaining = allowance < 0 ? -1 : Math.max(0, allowance - used);

    // Block if exceeding allowance (for limited plans)
    if (allowance >= 0 && requested > remaining) {
      return res.status(402).json({
        error: 'SMS allowance exceeded',
        message: `You have ${remaining} SMS left this month. Reduce recipients or purchase an SMS add-on.`,
        allowance,
        used,
        remaining
      });
    }

    // Send messages
    const results = [];
    for (const to of recipients) {
      try {
        const msg = await client.messages.create({ body: message, from, to });
        await db.collection('sms-history').add({
          messageSid: msg.sid,
          from,
          to,
          body: message,
          type: 'outbound',
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          shopDomain: shop,
          platform: 'Firebase Functions',
          conversationId: `conv_${to.replace('+', '')}_${from.replace('+', '')}`,
          status: 'sent'
        });
        results.push({ to, sid: msg.sid, status: 'sent' });
      } catch (e) {
        results.push({ to, error: e.message, status: 'failed' });
      }
    }

    const sentCount = results.filter(r => r.status === 'sent').length;

    res.json({
      success: true,
      sent: sentCount,
      failed: results.filter(r => r.status === 'failed').length,
      results,
      cycle: cycleKey,
      allowance,
      usedBefore: used,
      usedAfter: allowance < 0 ? used + sentCount : Math.min(allowance, used + sentCount),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ send-sms error:', error);
    res.status(500).json({ error: 'Failed to send SMS: ' + error.message });
  }
});

app.get('/api/contacts', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    if (!shopDomain || shopDomain === 'unknown-shop') return res.json([]);
    const snapshot = await db.collection('contacts')
      .where('shopDomain', '==', shopDomain)
      .limit(1000)
      .get();
    const contacts = snapshot.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(contacts);
  } catch (e) {
    console.error('contacts error', e);
    res.json([]);
  }
});

app.get('/api/contacts/template', (req, res) => {
  const csv = 'Name,Phone,Tags,Consent\nAlice Example,+447700900123,VIP,true\nBob Sample,+447700900456,newsletter,true\nCharlie Test,+447700900789,,false\n';
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="contacts-template.csv"');
  res.send(csv);
});
//
// Save contacts in bulk (CSV-backed or UI)
//
app.post('/api/contacts/bulk', async (req, res) => {
  try {
    const shopDomain = req.body.shop || req.query.shop || req.headers['x-shop-domain'];
    const contacts = Array.isArray(req.body.contacts) ? req.body.contacts : [];
    if (!shopDomain) return res.status(400).json({ error: 'Shop domain required' });
    if (contacts.length === 0) return res.status(400).json({ error: 'No contacts provided' });

    let saved = 0;
    const batch = db.batch();
    for (const c of contacts) {
      const phone = (c.phone || '').toString().trim();
      if (!phone) continue;
      // Deterministic doc id by shop+phone so re-uploads are idempotent
      const docId = Buffer.from(`${shopDomain}:${phone}`).toString('base64').replace(/=+$/,'');
      const ref = db.collection('contacts').doc(docId);
      batch.set(ref, {
        shopDomain,
        name: c.name || '',
        phone,
        tags: c.tags || '',
        consent: !!c.consent,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
      saved++;
    }
    await batch.commit();
    res.json({ success: true, saved });
  } catch (e) {
    console.error('contacts/bulk error', e);
    res.status(500).json({ error: 'Failed to save contacts: ' + e.message });
  }
});

//
// Create + send an SMS campaign (enforces monthly SMS allowance)
// Body: { shop, from, name, description?, message, recipients[] }
//
app.post('/api/campaigns/send', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { shop, from, name, description = '', message, recipients } = req.body || {};
    if (!shop || !from || !name || !message || !Array.isArray(recipients) || recipients.length === 0) {
      return res.status(400).json({ error: 'shop, from, name, message, and recipients[] are required' });
    }

    // Validate "from" belongs to this shop
    const senderSnap = await db.collection('purchased-numbers')
      .where('shopDomain', '==', shop)
      .where('number', '==', from)
      .limit(1).get();
    if (senderSnap.empty) return res.status(403).json({ error: 'Sender number not found for this shop' });

    // Enforce allowance (same logic as /api/send-sms)
    const now = new Date();
    const cycleKey = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    const startTs = admin.firestore.Timestamp.fromDate(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 0, 0, 0)));
    const endTs = admin.firestore.Timestamp.fromDate(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1, 0, 0, 0)));

    const subSnap = await db.collection('subscriptions')
      .where('shopDomain', '==', shop)
      .where('status', '==', 'active')
      .limit(1).get();

    let planIncluded = 0;
    if (!subSnap.empty) {
      const plan = subSnap.docs[0].data().plan;
      planIncluded = (BILLING_PLANS[plan]?.features?.smsIncluded ?? 0); // -1 unlimited
    }

    // Add-ons for the cycle
    let addonUnits = 0;
    try {
      const addonSnap = await db.collection('addons')
        .where('shopDomain', '==', shop)
        .where('type', '==', 'sms')
        .where('status', '==', 'active')
        .where('cycle', '==', cycleKey).get();
      addonUnits = addonSnap.docs.reduce((s, d) => s + (d.data().units || 0), 0);
    } catch { /* ignore */ }

    const allowance = planIncluded < 0 ? -1 : (planIncluded + addonUnits);
    const usedSnap = await db.collection('sms-history')
      .where('shopDomain', '==', shop)
      .where('type', '==', 'outbound')
      .where('timestamp', '>=', startTs)
      .where('timestamp', '<', endTs).get();
    const used = usedSnap.size;
    const requested = recipients.length;
    const remaining = allowance < 0 ? -1 : Math.max(0, allowance - used);

    if (allowance >= 0 && requested > remaining) {
      return res.status(402).json({
        error: 'SMS allowance exceeded',
        message: `You have ${remaining} SMS left this month. Reduce recipients or purchase an SMS add-on.`,
        allowance, used, remaining
      });
    }

    // Create campaign
    const campaignRef = db.collection('sms-campaigns').doc();
    await campaignRef.set({
      shopDomain: shop,
      name,
      description,
      from,
      message,
      recipientsTotal: recipients.length,
      sent: 0,
      failed: 0,
      status: 'sending',
      cycle: cycleKey,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const results = [];
    let sent = 0, failed = 0;

    for (const to of recipients) {
      try {
        const msg = await client.messages.create({ body: message, from, to });
        sent++;
        results.push({ to, sid: msg.sid, status: 'sent' });

        await db.collection('sms-history').add({
          messageSid: msg.sid,
          from, to, body: message,
          type: 'outbound',
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          shopDomain: shop,
          platform: 'Firebase Functions',
          conversationId: `conv_${to.replace('+','')}_${from.replace('+','')}`,
          status: 'sent',
          campaignId: campaignRef.id,
          campaignName: name
        });
      } catch (e) {
        failed++;
        results.push({ to, error: e.message, status: 'failed' });
      }
    }

    await campaignRef.update({
      sent, failed,
      status: 'completed',
      completedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, campaignId: campaignRef.id, sent, failed, results });
  } catch (e) {
    console.error('campaigns/send error', e);
    res.status(500).json({ error: 'Failed to send campaign: ' + e.message });
  }
});

// 3) GDPR customers/redact — ack immediately, then process
app.post('/webhooks/customers/redact', validateShopifyWebhook, (req, res) => {
  try {
    res.status(200).send('ok'); // ACK immediately

    setImmediate(async () => {
      try {
        const { shop_domain, customer } = req.body;
        const customerId = customer?.id;
        const customerEmail = customer?.email;
        const customerPhone = customer?.phone;

        console.log(`🗑️ GDPR Customer Erasure | Shop: ${shop_domain} | Customer: ${customerId}`);

        await db.collection('gdpr-audit').add({
          type: 'customer_redact',
          shopDomain: shop_domain,
          customerId,
          customerEmail,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          status: 'processing',
          platform: 'Firebase Functions'
        });

        let deletedRecords = 0;
        let anonymizedRecords = 0;

        // Anonymize purchased numbers
        if (customerPhone || customerEmail) {
          const numbersSnapshot = await db.collection('purchased-numbers')
            .where('shopDomain', '==', shop_domain)
            .get();

          const batch = db.batch();
          numbersSnapshot.docs.forEach(doc => {
            const data = doc.data();
            if (data.customerEmail === customerEmail ||
                data.customerPhone === customerPhone ||
                data.forwardTo === customerPhone) {
              batch.update(doc.ref, {
                customerEmail: '[REDACTED]',
                customerPhone: '[REDACTED]',
                forwardTo: data.forwardTo === customerPhone ? '[REDACTED]' : data.forwardTo,
                redactedAt: admin.firestore.FieldValue.serverTimestamp(),
                gdprCompliant: true
              });
              anonymizedRecords++;
            }
          });
          await batch.commit();
        }

        // Delete call history
        if (customerPhone) {
          const callsSnapshot = await db.collection('call-history')
            .where('shopDomain', '==', shop_domain)
            .get();
          const batch = db.batch();
          callsSnapshot.docs.forEach(doc => {
            const d = doc.data();
            if (d.from === customerPhone || d.to === customerPhone) {
              batch.delete(doc.ref);
              deletedRecords++;
            }
          });
          await batch.commit();
        }

        // Delete SMS history
        if (customerPhone) {
          const smsSnapshot = await db.collection('sms-history')
            .where('shopDomain', '==', shop_domain)
            .get();
          const batch = db.batch();
          smsSnapshot.docs.forEach(doc => {
            const d = doc.data();
            if (d.from === customerPhone || d.to === customerPhone) {
              batch.delete(doc.ref);
              deletedRecords++;
            }
          });
          await batch.commit();
        }

        // Delete call recordings
        const recordingsSnapshot = await db.collection('call-recordings')
          .where('shopDomain', '==', shop_domain)
          .get();
        const batch = db.batch();
        recordingsSnapshot.docs.forEach(doc => {
          const d = doc.data();
          if (d.customerPhone === customerPhone) {
            batch.delete(doc.ref);
            deletedRecords++;
          }
        });
        await batch.commit();

        await db.collection('gdpr-audit').add({
          type: 'customer_redact_completed',
          shopDomain: shop_domain,
          deletedRecords,
          anonymizedRecords,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          status: 'completed',
          platform: 'Firebase Functions'
        });

        console.log(`✅ GDPR Customer Erasure completed | Deleted: ${deletedRecords} | Anonymized: ${anonymizedRecords}`);
      } catch (error) {
        console.error('GDPR customer_redact background error', error);
      }
    });
  } catch (e) {
    res.status(200).send('ok');
  }
});

// **WEBHOOK: Shop Data Erasure (App Uninstall)** - FAST RESPONSE VERSION
app.post('/webhooks/shop/redact', validateShopifyWebhook, async (req, res) => {
  try {
    const { shop_domain } = req.body;
    console.log(`🏪 GDPR Shop Erasure queued for: ${shop_domain}`);

    // RESPOND TO SHOPIFY IMMEDIATELY (under 5 seconds)
    res.status(200).json({
      message: 'Shop data erasure initiated',
      shop_domain: shop_domain,
      status: 'processing',
      timestamp: new Date().toISOString()
    });

    // Log the webhook call for audit trail
    await db.collection('gdpr-audit').add({
      type: 'shop_redact',
      shopDomain: shop_domain,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'queued',
      platform: 'Firebase Functions'
    });

    // BACKGROUND PROCESSING (don't block response)
    setImmediate(async () => {
      try {
        let deletedCollections = 0;
        let releasedNumbers = 0;

        console.log(`🔄 Starting background cleanup for: ${shop_domain}`);

        // Release all Twilio numbers back to pool
        try {
          const numbersSnapshot = await db.collection('purchased-numbers')
            .where('shopDomain', '==', shop_domain)
            .get();

          if (!numbersSnapshot.empty) {
            const client = getTwilioClient();
            
            for (const doc of numbersSnapshot.docs) {
              const numberData = doc.data();
              
              if (numberData.twilioSid) {
                try {
                  await client.incomingPhoneNumbers(numberData.twilioSid).remove();
                  releasedNumbers++;
                  console.log(`📞 Released Twilio number: ${numberData.number}`);
                } catch (twilioError) {
                  console.warn(`⚠️ Could not release ${numberData.number}:`, twilioError.message);
                }
              }
            }
          }
        } catch (twilioError) {
          console.warn('⚠️ Twilio cleanup error:', twilioError.message);
        }

        // Delete all shop data from Firebase collections
        const collections = [
          'subscriptions',
          'purchased-numbers',
          'call-history',
          'sms-history',
          'call-recordings',
          'sms-campaigns',
          'addons',
          'contacts'
        ];

        for (const collectionName of collections) {
          try {
            const snapshot = await db.collection(collectionName)
              .where('shopDomain', '==', shop_domain)
              .get();

            if (!snapshot.empty) {
              const batch = db.batch();
              snapshot.docs.forEach(doc => {
                batch.delete(doc.ref);
              });
              await batch.commit();
              deletedCollections++;
              console.log(`🗑️ Deleted ${snapshot.size} records from ${collectionName}`);
            }
          } catch (collectionError) {
            console.warn(`⚠️ Error cleaning ${collectionName}:`, collectionError.message);
          }
        }

        // Update audit log
        await db.collection('gdpr-audit').add({
          type: 'shop_redact_completed',
          shopDomain: shop_domain,
          deletedCollections,
          releasedNumbers,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          status: 'completed',
          platform: 'Firebase Functions'
        });

        console.log(`✅ GDPR Shop Erasure completed for ${shop_domain} | Collections: ${deletedCollections} | Released Numbers: ${releasedNumbers}`);

      } catch (backgroundError) {
        console.error(`❌ Background cleanup failed for ${shop_domain}:`, backgroundError);
        
        // Log the error
        await db.collection('gdpr-audit').add({
          type: 'shop_redact_failed',
          shopDomain: shop_domain,
          error: backgroundError.message,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
          status: 'failed',
          platform: 'Firebase Functions'
        }).catch(() => {});
      }
    });

  } catch (error) {
    console.error('❌ GDPR Shop Erasure error:', error);
    // Always return 200 to Shopify to prevent retries
    res.status(200).json({
      message: 'Shop data erasure queued with errors',
      shop_domain: req.body?.shop_domain || 'unknown',
      status: 'error',
      timestamp: new Date().toISOString()
    });
  }
});
// **GDPR Audit Endpoint (Optional - for monitoring)**
app.get('/api/gdpr/audit', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    
    const auditRef = db.collection('gdpr-audit')
      .where('shopDomain', '==', shopDomain)
      .orderBy('timestamp', 'desc')
      .limit(50);
    
    const snapshot = await auditRef.get();
    
    const auditLog = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      timestamp: doc.data().timestamp?.toDate?.()?.toISOString?.()
    }));

    res.json({
      shop_domain: shopDomain,
      audit_records: auditLog,
      total_records: auditLog.length,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ GDPR Audit error:', error);
    res.status(500).json({ error: 'Failed to fetch audit log: ' + error.message });
  }
});
// **API: Delete/Release Number**
app.delete('/api/numbers/:id', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { id } = req.params;
    const shopDomain = getShopFromRequest(req);

    console.log(`🗑️ Releasing number ${id} for shop: ${shopDomain}`);

    // Get number details
    const doc = await db.collection('purchased-numbers').doc(id).get();
    
    if (!doc.exists) {
      return res.status(404).json({ error: 'Number not found' });
    }

    const numberData = doc.data();
    
    // Verify ownership
    if (numberData.shopDomain !== shopDomain) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Release from Twilio
    if (numberData.twilioSid) {
      try {
        await client.incomingPhoneNumbers(numberData.twilioSid).remove();
        console.log('✅ Number released from Twilio');
      } catch (twilioError) {
        console.warn('⚠️ Twilio release warning:', twilioError.message);
      }
    }

    // Remove from Firebase
    await db.collection('purchased-numbers').doc(id).delete();
    console.log('✅ Number removed from database');

    res.json({
      success: true,
      message: `Number ${numberData.number} released successfully`,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Error releasing number:', error);
    res.status(500).json({
      error: 'Failed to release number: ' + error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// **API: My Numbers**
app.get('/api/my-numbers', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    console.log(`📱 Fetching numbers for shop: ${shopDomain}`);
    
    if (shopDomain === 'unknown-shop') {
      return res.status(400).json({
        error: 'Shop domain required',
        message: 'Please provide shop parameter in URL'
      });
    }
    
    const numbersRef = db.collection('purchased-numbers')
      .where('shopDomain', '==', shopDomain);
    const snapshot = await numbersRef.get();
    
    const numbers = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      purchaseDate: doc.data().purchaseDate?.toDate?.()?.toISOString?.()?.split('T')[0] || new Date().toISOString().split('T')[0]
    }));

    console.log(`📱 Found ${numbers.length} numbers for ${shopDomain}`);
    res.json(numbers);
    
  } catch (error) {
    console.error('❌ Error fetching numbers:', error);
    res.status(500).json({ error: 'Failed to fetch numbers: ' + error.message });
  }
});

// **API: Update Number Settings**
app.patch('/api/numbers/:id', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { id } = req.params;
    const { forwardTo, status } = req.body;
    const shopDomain = getShopFromRequest(req);

    console.log(`⚙️ Updating number ${id} settings | forwardTo: ${forwardTo}`);

    await db.collection('purchased-numbers').doc(id).update({
      forwardTo: forwardTo,
      status: status,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    if (forwardTo) {
      const doc = await db.collection('purchased-numbers').doc(id).get();
      const numberData = doc.data();
      
      if (numberData?.twilioSid) {
        const functionUrl = req.get('host');
        const functionBaseUrl = `https://${functionUrl}`;
        
          await client.incomingPhoneNumbers(numberData.twilioSid).update({
            voiceUrl: `${functionBaseUrl}/api/voice-webhook?forward=${encodeURIComponent(forwardTo)}&id=${encodeURIComponent(id)}&shop=${encodeURIComponent(shopDomain)}`
          });
        console.log('✅ Twilio webhook updated');
      }
    }

    res.json({
      success: true,
      message: `Settings saved! Calls will forward to ${forwardTo}`,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Error updating number settings:', error);
    res.status(500).json({ error: 'Failed to update settings: ' + error.message });
  }
});

// **API: Call History**
app.get('/api/call-history', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    
    if (shopDomain === 'unknown-shop') {
      return res.status(400).json({
        error: 'Shop domain required',
        message: 'Please provide shop parameter in URL'
      });
    }
    
    const callsRef = db.collection('call-history')
      .where('shopDomain', '==', shopDomain)
      .orderBy('timestamp', 'desc')
      .limit(100);
    
    const snapshot = await callsRef.get();
    
    const calls = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      date: doc.data().timestamp?.toDate?.()?.toISOString?.()?.split('T')[0] || new Date().toISOString().split('T')[0],
      time: doc.data().timestamp?.toDate?.()?.toTimeString?.()?.split(' ')[0] || new Date().toTimeString().split(' ')[0]
    }));

    console.log(`📞 Found ${calls.length} calls for ${shopDomain}`);
    res.json(calls);
    
  } catch (error) {
    console.error('❌ Error fetching call history:', error);
    res.status(500).json({ error: 'Failed to fetch call history: ' + error.message });
  }
});

// **API: Voice Webhook**
app.post('/api/voice-webhook', async (req, res) => {
  try {
    const { From, To, CallSid } = req.body;
    const forwardTo = req.query.forward;
    const numberId = req.query.id;
    const shopDomain = req.query.shop || 'unknown';

    console.log(`📞 Incoming call from ${From} to ${To} | Forward: ${forwardTo}`);

    // Log call to Firebase
    await db.collection('call-history').add({
      callSid: CallSid,
      from: From,
      to: To,
      type: 'inbound',
      status: 'received',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      numberId: numberId,
      shopDomain: shopDomain,
      duration: 0,
      platform: 'Firebase Functions'
    });

    // Generate TwiML response
    const twiml = new twilio.twiml.VoiceResponse();
    
    if (forwardTo && forwardTo !== '') {
      console.log('📲 Forwarding call to:', forwardTo);
      twiml.say('Please hold while we connect you to the store owner.');
      twiml.dial(forwardTo);
    } else {
      twiml.say({
        voice: 'alice'
      }, 'Hello! Thank you for calling this Shopify store. The owner has not set up call forwarding yet. Please try again later, or send us a text message. Have a great day!');
    }

    res.type('text/xml');
    res.send(twiml.toString());
    
  } catch (error) {
    console.error('❌ Voice webhook error:', error);
    const twiml = new twilio.twiml.VoiceResponse();
    twiml.say('Thank you for calling. Please try again later.');
    res.type('text/xml');
    res.send(twiml.toString());
  }
});

// Add this AFTER your existing voice-webhook route
app.post('/voice-webhook', async (req, res) => {
  try {
    const { From, To, CallSid } = req.body;
    const forwardTo = req.query.forward;
    const numberId = req.query.id;
    const shopDomain = req.query.shop || 'unknown';

    console.log(`📞 Direct webhook call from ${From} to ${To} | Forward: ${forwardTo}`);

    // Same logic as your /api/voice-webhook
    await db.collection('call-history').add({
      callSid: CallSid,
      from: From,
      to: To,
      type: 'inbound',
      status: 'received',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      numberId: numberId,
      shopDomain: shopDomain,
      duration: 0,
      platform: 'Firebase Functions'
    });

    const twiml = new twilio.twiml.VoiceResponse();
    
    if (forwardTo && forwardTo !== '') {
      console.log('📲 Forwarding call to:', forwardTo);
      twiml.say('Please hold while we connect you.');
      twiml.dial(forwardTo);
    } else {
      twiml.say('Thank you for calling. Call forwarding is not set up yet.');
    }

    res.type('text/xml');
    res.send(twiml.toString());
    
  } catch (error) {
    console.error('❌ Voice webhook error:', error);
    const twiml = new twilio.twiml.VoiceResponse();
    twiml.say('Thank you for calling. Please try again later.');
    res.type('text/xml');
    res.send(twiml.toString());
  }
});

// **API: Bundle Diagnostics**
app.get('/api/bundle-diagnostics', async (req, res) => {
  try {
    console.log('🔍 Bundle diagnostics requested');
    
    const diagnostics = {
      timestamp: new Date().toISOString(),
      platform: 'Firebase Functions (Node 20)',
      bundleSid: UK_BUNDLE_SID,
      addressSid: UK_ADDRESS_SID,
      environment: {
        twilioAccountSid: TWILIO_ACCOUNT_SID ? 'Set ✅' : 'Missing ❌',
        twilioAuthToken: TWILIO_AUTH_TOKEN ? 'Set ✅' : 'Missing ❌',
        ukBundle: UK_BUNDLE_SID ? 'Set ✅' : 'Missing ❌',
        ukAddress: UK_ADDRESS_SID ? 'Set ✅' : 'Missing ❌'
      },
      bundleDetails: null,
      addressDetails: null,
      recommendations: []
    };

    // Only check bundle details if Twilio is configured
    if (UK_BUNDLE_SID && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
      try {
        const bundleResponse = await fetch(`https://accounts.twilio.com/v1/Bundles/${UK_BUNDLE_SID}`, {
          headers: {
            'Authorization': `Basic ${Buffer.from(`${TWILIO_ACCOUNT_SID}:${TWILIO_AUTH_TOKEN}`).toString('base64')}`
          }
        });
        
        if (bundleResponse.ok) {
          const bundleData = await bundleResponse.json();
          diagnostics.bundleDetails = {
            sid: bundleData.sid,
            status: bundleData.status,
            friendlyName: bundleData.friendly_name,
            numberType: bundleData.number_type,
            isoCountry: bundleData.iso_country,
            endUserType: bundleData.end_user_type
          };
          
          if (bundleData.status !== 'approved') {
            diagnostics.recommendations.push(`❌ Bundle status: ${bundleData.status} (needs to be 'approved')`);
          }
          
        } else {
          diagnostics.bundleDetails = { error: 'Failed to fetch bundle details' };
        }
      } catch (bundleError) {
        diagnostics.bundleDetails = { error: bundleError.message };
      }
    }

    // Only check address details if Twilio is configured
    if (UK_ADDRESS_SID && TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN) {
      try {
        const client = getTwilioClient();
        const address = await client.addresses(UK_ADDRESS_SID).fetch();
        diagnostics.addressDetails = {
          sid: address.sid,
          customerName: address.customerName,
          street: address.street,
          city: address.city,
          region: address.region,
          postalCode: address.postalCode,
          isoCountry: address.isoCountry,
          verified: address.verified
        };
        
        if (!address.verified) {
          diagnostics.recommendations.push('❌ Address is not verified');
        }
        
      } catch (addressError) {
        diagnostics.addressDetails = { error: addressError.message };
      }
    }

    // Add general recommendations
    if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN) {
      diagnostics.recommendations.push('🔧 Set Twilio credentials: TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN');
    }
    
    if (!UK_BUNDLE_SID) {
      diagnostics.recommendations.push('🔧 Create UK regulatory bundle at https://console.twilio.com/us1/develop/phone-numbers/regulatory-bundles');
    }
    
    if (!UK_ADDRESS_SID) {
      diagnostics.recommendations.push('🔧 Create UK address at https://console.twilio.com/us1/develop/phone-numbers/addresses');
    }

    res.json(diagnostics);
    
  } catch (error) {
    console.error('❌ Diagnostics error:', error);
    res.status(500).json({ error: error.message });
  }
});

// **DEBUG ENDPOINT - TEMPORARY**
app.get('/api/debug/all-data', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    
    // Get all purchased numbers
    const allNumbers = await db.collection('purchased-numbers').get();
    const numbersData = allNumbers.docs.map(doc => ({
      id: doc.id,
      shopDomain: doc.data().shopDomain,
      number: doc.data().number,
      status: doc.data().status
    }));
    
    // Get all subscriptions
    const allSubs = await db.collection('subscriptions').get();
    const subsData = allSubs.docs.map(doc => ({
      id: doc.id,
      shopDomain: doc.data().shopDomain,
      plan: doc.data().plan,
      status: doc.data().status
    }));
    
    res.json({
      currentShop: shopDomain,
      totalNumbers: numbersData.length,
      totalSubs: subsData.length,
      allNumbers: numbersData,
      allSubs: subsData,
      message: '🚨 REMOVE THIS DEBUG ENDPOINT IN PRODUCTION!'
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add these endpoints to your index.js AFTER the existing endpoints

// **API: Available SMS Numbers**
app.get('/api/available-sms', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { limit = 50, country = 'GB' } = req.query;
    
    console.log(`🔍 Fetching SMS-capable numbers for ${country}`);
    
    const numbers = await client.availablePhoneNumbers(country).mobile.list({
      smsEnabled: true,
      limit: Math.min(parseInt(limit), 100)
    });

    const formattedNumbers = numbers.map((number, index) => ({
      id: `sms_${index}`,
      number: number.phoneNumber,
      area: number.locality || 'Mobile',
      price: 4.99,
      priceText: '£4.99/month',
      tier: 'sms',
      type: 'SMS Mobile',
      capabilities: number.capabilities,
      available: true,
      country: country,
      smsEnabled: true,
      timestamp: new Date().toISOString()
    }));

    res.json(formattedNumbers);
    
  } catch (error) {
    console.error('❌ Error fetching SMS numbers:', error);
    res.status(500).json({
      error: 'Failed to fetch SMS numbers: ' + error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// **API: Landline Numbers (user's landline numbers)**
app.get('/api/landline-numbers', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    console.log(`📞 Fetching landline numbers for shop: ${shopDomain}`);
    
    const numbersRef = db.collection('purchased-numbers')
      .where('shopDomain', '==', shopDomain)
      .where('type', 'in', ['landline', 'voice', 'geographic']);
    const snapshot = await numbersRef.get();
    
    const numbers = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      purchaseDate: doc.data().purchaseDate?.toDate?.()?.toISOString?.()?.split('T')[0] || new Date().toISOString().split('T')[0]
    }));

    console.log(`📞 Found ${numbers.length} landline numbers for ${shopDomain}`);
    res.json(numbers);
    
  } catch (error) {
    console.error('❌ Error fetching landline numbers:', error);
    res.status(500).json({ error: 'Failed to fetch landline numbers: ' + error.message });
  }
});

// **API: SMS Numbers (user's SMS numbers)**
app.get('/api/sms-numbers', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    console.log(`💬 Fetching SMS numbers for shop: ${shopDomain}`);
    
    const numbersRef = db.collection('purchased-numbers')
      .where('shopDomain', '==', shopDomain)
      .where('type', '==', 'sms');
    const snapshot = await numbersRef.get();
    
    const numbers = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      purchaseDate: doc.data().purchaseDate?.toDate?.()?.toISOString?.()?.split('T')[0] || new Date().toISOString().split('T')[0]
    }));

    console.log(`💬 Found ${numbers.length} SMS numbers for ${shopDomain}`);
    res.json(numbers);
    
  } catch (error) {
    console.error('❌ Error fetching SMS numbers:', error);
    res.status(500).json({ error: 'Failed to fetch SMS numbers: ' + error.message });
  }
});

// **API: Call Recordings**
app.get('/api/recordings', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    console.log(`🎵 Fetching recordings for shop: ${shopDomain}`);
    
    const recordingsRef = db.collection('call-recordings')
      .where('shopDomain', '==', shopDomain)
      .orderBy('timestamp', 'desc')
      .limit(100);
    
    const snapshot = await recordingsRef.get();
    
    const recordings = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      date: doc.data().timestamp?.toDate?.()?.toISOString?.()?.split('T')[0] || new Date().toISOString().split('T')[0]
    }));

    console.log(`🎵 Found ${recordings.length} recordings for ${shopDomain}`);
    res.json(recordings);
    
  } catch (error) {
    console.error('❌ Error fetching recordings:', error);
    res.status(500).json({ error: 'Failed to fetch recordings: ' + error.message });
  }
});

// **API: SMS Campaigns**
app.get('/api/campaigns', async (req, res) => {
  try {
    const shopDomain = getShopFromRequest(req);
    console.log(`🚀 Fetching campaigns for shop: ${shopDomain}`);
    
    const campaignsRef = db.collection('sms-campaigns')
      .where('shopDomain', '==', shopDomain)
      .orderBy('createdAt', 'desc');
    
    const snapshot = await campaignsRef.get();
    
    const campaigns = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    console.log(`🚀 Found ${campaigns.length} campaigns for ${shopDomain}`);
    res.json(campaigns);
    
  } catch (error) {
    console.error('❌ Error fetching campaigns:', error);
    res.status(500).json({ error: 'Failed to fetch campaigns: ' + error.message });
  }
});
// **API: Call Complete Status**
app.post('/api/call-complete', async (req, res) => {
  try {
    const { CallDuration, CallStatus, DialCallStatus } = req.body;
    const callId = req.query.callId;
    
    console.log(`📞 Call completed: ${callId} | Duration: ${CallDuration}s | Status: ${CallStatus}`);
    
    if (callId) {
      await db.collection('call-history').doc(callId).update({
        duration: parseInt(CallDuration) || 0,
        endStatus: CallStatus,
        dialStatus: DialCallStatus,
        answered: CallStatus === 'completed',
        endTime: new Date().toISOString(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    
    res.status(200).send('OK');
    
  } catch (error) {
    console.error('❌ Call complete error:', error);
    res.status(500).send('Error');
  }
});

// **ENHANCED SMS Webhook with Reply Chain**
app.post('/api/sms-webhook', async (req, res) => {
  try {
    const { From, To, Body, MessageSid, NumMedia } = req.body;

    console.log(`💬 Enhanced SMS from ${From}: ${Body}`);

    // Log SMS with conversation tracking
    const smsDoc = await db.collection('sms-history').add({
      messageSid: MessageSid,
      from: From,
      to: To,
      body: Body,
      type: 'inbound',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      shopDomain: 'auto-detected', // You can enhance this
      platform: 'Firebase Functions',
      hasMedia: NumMedia && parseInt(NumMedia) > 0,
      mediaCount: parseInt(NumMedia) || 0,
      conversationId: `conv_${From.replace('+', '')}_${To.replace('+', '')}`,
      status: 'received'
    });

    const twiml = new twilio.twiml.MessagingResponse();
    twiml.message('Thank you for your message! We received it and will get back to you soon. For immediate support, contact support@team-connect.co.uk 📞');

    res.type('text/xml');
    res.send(twiml.toString());
    
  } catch (error) {
    console.error('❌ Enhanced SMS webhook error:', error);
    res.type('text/xml');
    res.send('<Response></Response>');
  }
});

// **API: SMS Reply**
app.post('/api/sms/reply', async (req, res) => {
  try {
    const client = getTwilioClient();
    const { to, body, fromNumber } = req.body;
    const shopDomain = getShopFromRequest(req);

    console.log(`💬 Sending SMS reply from ${fromNumber} to ${to}: ${body}`);

    const message = await client.messages.create({
      body: body,
      from: fromNumber,
      to: to
    });

    // Log outbound SMS
    await db.collection('sms-history').add({
      messageSid: message.sid,
      from: fromNumber,
      to: to,
      body: body,
      type: 'outbound',
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      shopDomain: shopDomain,
      platform: 'Firebase Functions',
      conversationId: `conv_${to.replace('+', '')}_${fromNumber.replace('+', '')}`,
      status: 'sent'
    });

    res.json({
      success: true,
      messageSid: message.sid,
      message: 'SMS sent successfully',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ SMS reply error:', error);
    res.status(500).json({
      error: 'Failed to send SMS: ' + error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// **API: SMS Conversation**
app.get('/api/sms/conversation/:conversationId', async (req, res) => {
  try {
    const { conversationId } = req.params;
    const shopDomain = getShopFromRequest(req);
    
    console.log(`💬 Fetching conversation: ${conversationId}`);
    
    const messagesRef = db.collection('sms-history')
      .where('conversationId', '==', conversationId)
      .orderBy('timestamp', 'asc')
      .limit(100);
    
    const snapshot = await messagesRef.get();
    
    const messages = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      timestamp: doc.data().timestamp?.toDate?.()?.toISOString?.() || new Date().toISOString()
    }));

    res.json({
      conversationId,
      messages,
      totalMessages: messages.length,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Error fetching conversation:', error);
    res.status(500).json({ error: 'Failed to fetch conversation: ' + error.message });
  }
});

// **API: Recording Status Callback**
app.post('/api/recording-status', async (req, res) => {
  try {
    const { RecordingUrl, RecordingSid, CallSid, RecordingDuration } = req.body;
    
    console.log(`🎵 Recording completed: ${RecordingSid} | Duration: ${RecordingDuration}s`);
    
    await db.collection('call-recordings').add({
      recordingSid: RecordingSid,
      callSid: CallSid,
      recordingUrl: RecordingUrl,
      duration: `${RecordingDuration}s`,
      durationSeconds: parseInt(RecordingDuration),
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      status: 'completed',
      shopDomain: 'auto-detected',
      platform: 'Firebase Functions'
    });
    
    res.status(200).send('OK');
    
  } catch (error) {
    console.error('❌ Recording status error:', error);
    res.status(500).send('Error');
  }
});
// **Error Handler**
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

exports.api = functions.https.onRequest({
  region: 'europe-west2',     // pick the closest region to your users
  timeoutSeconds: 540,
  memory: '1GiB',
  minInstances: 1,            // keep one instance warm to avoid cold-starts on webhooks
  maxInstances: 100,
  cors: true
}, app);
