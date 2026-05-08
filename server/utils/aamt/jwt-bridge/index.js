"use strict";
/**
 * @aamt/anythingllm-jwt-bridge
 *
 * Pre-handler for the AnythingLLM-AAMT fork. Verifies the platform JWT
 * minted by WP at GET /wp-json/mm/v1/auth/jwt and gates access by WP role
 * (default: 'administrator') so non-admins never reach AnythingLLM's
 * first-time-setup or admin pages.
 *
 * The fork's existing session/cookie handling is preserved — this middleware
 * only ensures the requester is authenticated and authorized at the platform
 * level. Once past this gate the fork behaves normally.
 *
 * Wiring: see /Users/.../AnythingLLM-AAMT/fork/server/index.js — middleware
 * is mounted before `app.use("/api", apiRouter)` so the /api surface and
 * the SPA frontend both inherit the gate.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.exchangePlatformJWT = exchangePlatformJWT;
exports.jwtBridgeMiddleware = jwtBridgeMiddleware;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const DEFAULT_ALLOWED_ROLES = ['administrator'];
const DEFAULT_WORKSPACE_TOKEN_TTL_SEC = 900;
const COOKIE_NAME = 'aamt_session';
/**
 * Verify a platform JWT and produce a workspace token for AnythingLLM.
 * Throws an Error tagged with `code` (BridgeError['code']) on failure.
 */
function exchangePlatformJWT(rawToken, config) {
    if (!rawToken) {
        throw bridgeError('NO_TOKEN', 'no platform JWT presented');
    }
    const verifyOpts = {
        algorithms: ['HS256'],
        issuer: 'asamanthinks-wp',
    };
    let claims;
    try {
        claims = jsonwebtoken_1.default.verify(rawToken, config.jwtSecret, verifyOpts);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : 'verify failed';
        if (msg.toLowerCase().includes('expired')) {
            throw bridgeError('EXPIRED_TOKEN', 'platform JWT expired');
        }
        if (msg.toLowerCase().includes('iss')) {
            throw bridgeError('WRONG_ISSUER', 'platform JWT issuer mismatch');
        }
        throw bridgeError('INVALID_TOKEN', `platform JWT invalid: ${msg}`);
    }
    // Role/cap/allowlist gate.
    if (!config.openMode) {
        const userIdStr = String(claims.sub);
        const allowedRoles = config.allowedRoles ?? DEFAULT_ALLOWED_ROLES;
        const allowedCaps = config.allowedCaps ?? [];
        const allowlisted = (config.betaAllowlist ?? []).includes(userIdStr);
        const hasRole = (claims.roles ?? []).some((r) => allowedRoles.includes(r));
        const hasCap = (claims.mm_caps ?? []).some((c) => allowedCaps.includes(c));
        if (!allowlisted && !hasRole && !hasCap) {
            throw bridgeError('ROLE_INELIGIBLE', `roles=[${(claims.roles ?? []).join(',')}] caps=[${(claims.mm_caps ?? []).join(',')}] not in allowedRoles=[${allowedRoles.join(',')}] / allowedCaps=[${allowedCaps.join(',')}]`);
        }
    }
    const ttl = config.workspaceTokenTtlSec ?? DEFAULT_WORKSPACE_TOKEN_TTL_SEC;
    const expires_at = Math.floor(Date.now() / 1000) + ttl;
    const isAdmin = (claims.roles ?? []).includes('administrator');
    const workspaceToken = jsonwebtoken_1.default.sign({
        sub: String(claims.sub),
        email: claims.email,
        username: claims.username,
        workspace: deriveWorkspaceId(claims),
        is_admin: isAdmin,
        iat: Math.floor(Date.now() / 1000),
        exp: expires_at,
    }, config.jwtSecret, { algorithm: 'HS256' });
    return {
        token: workspaceToken,
        workspace_id: deriveWorkspaceId(claims),
        user_id: String(claims.sub),
        email: claims.email,
        is_admin: isAdmin,
        expires_at,
    };
}
/**
 * Express middleware factory.
 *
 * Reads the platform JWT from (in priority order):
 *   1. `Authorization: Bearer <jwt>` header
 *   2. `aamt_session` cookie (set by the platform login flow)
 *   3. `?aamt_jwt=<jwt>` query param (one-shot; for the redirect-from-WP boot)
 *
 * On success: attaches `req.aamtSession` and calls next().
 * On failure: 302 redirects browser requests to /login on the platform; for
 * /api/* requests returns a structured 401/403 JSON envelope.
 */
function jwtBridgeMiddleware(config) {
    const bypass = config.bypassPaths ?? ['/api/ping', '/api/migrate'];
    const loginUrl = config.loginRedirectUrl ??
        'https://asamanthinks.com/login?next=' +
            encodeURIComponent('https://llm.asamanthinks.com/');
    // Static frontend asset extensions that must be served unauthenticated.
    // Without this, requests for `/assets/*.js`, `/favicon.png`, etc. get
    // 302-redirected to the platform login page; browsers follow the redirect,
    // receive HTML (text/html), and module scripts fail with a MIME mismatch
    // error on iOS Safari (the page is unusable on iPad).
    const STATIC_ASSET_RE = /\.(js|mjs|css|map|wasm|json|png|jpe?g|gif|svg|webp|ico|webm|mp4|mp3|wav|ogg|woff2?|ttf|otf|eot)(\?.*)?$/i;
    return function bridge(req, res, next) {
        // Bypass for healthchecks (lets Docker probe pass without auth).
        if (bypass.some((p) => req.path === p || req.path?.startsWith(p))) {
            return next();
        }
        // Bypass static frontend assets so the SPA bootstraps with correct MIME.
        // These are hashed/public Vite build outputs — no auth-sensitive data.
        if (req.path && STATIC_ASSET_RE.test(req.path)) {
            return next();
        }
        const rawToken = readToken(req);
        try {
            const workspace = exchangePlatformJWT(rawToken, config);
            req.aamtSession = workspace;
            // Also set the cookie so subsequent same-origin requests don't need
            // the query param, and the SPA can read the email/admin status.
            res.cookie?.(COOKIE_NAME, workspace.token, {
                httpOnly: true,
                secure: true,
                sameSite: 'lax',
                maxAge: (config.workspaceTokenTtlSec ?? DEFAULT_WORKSPACE_TOKEN_TTL_SEC) * 1000,
                path: '/',
            });
            next();
        }
        catch (err) {
            const e = err;
            const code = e.code ?? 'INVALID_TOKEN';
            // For API requests, return structured JSON so the SPA can react.
            if ((req.path || '').startsWith('/api/')) {
                const status = code === 'ROLE_INELIGIBLE' ? 403 : 401;
                res.status(status).json({ error: code, message: e.message });
                return;
            }
            // For browser navigations, 302 to the platform login.
            res.redirect(302, loginUrl);
        }
    };
}
function readToken(req) {
    const auth = req.headers?.authorization;
    if (auth?.startsWith('Bearer ')) {
        return auth.slice('Bearer '.length).trim();
    }
    // Manual cookie parse (don't require cookie-parser as a fork dep).
    const cookieHeader = req.headers?.cookie;
    if (cookieHeader) {
        for (const part of cookieHeader.split(';')) {
            const trimmed = part.trim();
            if (trimmed.startsWith(COOKIE_NAME + '=')) {
                return decodeURIComponent(trimmed.slice(COOKIE_NAME.length + 1));
            }
        }
    }
    const queryToken = req.query?.aamt_jwt ?? '';
    return queryToken;
}
function deriveWorkspaceId(claims) {
    return `ws_${claims.sub}`;
}
function bridgeError(code, message) {
    const err = new Error(message);
    err.code = code;
    err.message = message;
    return err;
}
