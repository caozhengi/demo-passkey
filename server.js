const Koa = require('koa');
const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const crypto = require('crypto');

const app = new Koa();
const router = new Router();
const domain = 'passkey.7760442.xyz';

let users = {}; // 存储用户信息
let currentChallenges = {}; // 存储每个用户的challenge

// base64分别标准格式和URL安全格式，比较时需要先转换为标准格式
function compareBase64(base64_1, base64_2) {
    const normalize = str => str.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(str.length / 4) * 4, '=');
    return normalize(base64_1) === normalize(base64_2);
}

// 生成随机challenge
function generateChallenge() {
    return crypto.randomBytes(32).toString('base64');
}

// 注册
router.post('/cgi/register', async (ctx) => {
    const { username, attestationResponse } = ctx.request.body;

    const { id, rawId, response, type } = attestationResponse;
    const { clientDataJSON, attestationObject } = response;

    const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64').toString('utf-8'));
    console.log(username, clientData, currentChallenges[username]);

    if (!compareBase64(clientData.challenge, currentChallenges[username])) {
        ctx.body = { status: 'failed', message: 'Invalid challenge' };
        return;
    }

    // Here you should verify the attestationObject and store the credential
    users[username] = {
        id: username,
        credentials: [{ id, rawId, response, type }],
    };

    ctx.body = { status: '注册成功' };
});

// 登入
router.post('/cgi/login', async (ctx) => {
    const { username, assertionResponse } = ctx.request.body;

    const user = users[username];
    if (!user) {
        ctx.body = { status: 'failed', message: 'User not found' };
        return;
    }

    const { id, rawId, response, type } = assertionResponse;
    const { clientDataJSON, authenticatorData, signature, userHandle } = response;

    const clientData = JSON.parse(Buffer.from(clientDataJSON, 'base64').toString('utf-8'));
    if (!compareBase64(clientData.challenge, currentChallenges[username])) {
        ctx.body = { status: 'failed', message: 'Invalid challenge' };
        return;
    }

    // 省略验证 authenticatorData 和 signature

    ctx.body = { status: '登入成功, 服务器存在您的信息' };
});

// 获取注册/登入配置
router.get('/cgi/getOptions', async (ctx) => {
    const { username } = ctx.query;

    const user = users[username];
    const challenge = generateChallenge();
    currentChallenges[username] = challenge;

    if (!user) {
        // 生成注册配置
        const options = {
            challenge: challenge,
            rp: { name: 'Passkey Example', id: domain },
            user: {
                id: Buffer.from(username).toString('base64'),
                name: username,
                displayName: username,
            },
            pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
            attestation: 'direct',
        };
        ctx.body = options;
    } else {
        // 生成登入配置
        const options = {
            challenge: challenge,
            allowCredentials: user.credentials.map(cred => ({
                id: cred.rawId,
                type: 'public-key',
            })),
            timeout: 60000,
            userVerification: 'preferred',
        };
        ctx.body = options;
    }
});

app.use(bodyParser());
app.use(router.routes()).use(router.allowedMethods());

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
