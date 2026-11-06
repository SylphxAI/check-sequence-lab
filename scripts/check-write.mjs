import { writeFileSync } from 'node:fs';
const env = process.env;
const mask = x => console.log(`::add-mask::${x}`);
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function request(url, options = {}) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(30000), ...options });
  const payload = await response.json();
  return { status: response.status, payload };
}
function requireOk(reply, label) {
  if (reply.status < 200 || reply.status >= 300) throw Error(`${label}: HTTP ${reply.status}`);
  return reply.payload;
}
async function main() {
  const repository = env.GITHUB_REPOSITORY;
  if (!env.PROBE_CI_NAME || !/^orgs\/[A-Za-z0-9_-]+\/trust_policies\/[A-Za-z0-9_-]+$/.test(env.PROBE_TRUST_POLICY || '')) throw Error('Missing exchange configuration');
  const oidcUrl = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  oidcUrl.searchParams.set('audience', 'sylphx-access');
  const oidc = requireOk(await request(oidcUrl, {headers:{authorization:`Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`}}), 'OIDC');
  mask(oidc.value);
  const issued = requireOk(await request('https://api.sylphx.com/v1/access/github/token', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:env.PROBE_CI_NAME,token:oidc.value})}), 'Access');
  if (typeof issued.api_key !== 'string' || !issued.api_key) throw Error('No Access key');
  mask(issued.api_key);
  const active = issued.active_after_ms ?? 0;
  if (!Number.isInteger(active) || active < 0 || active > 60000) throw Error('Invalid activation interval');
  await sleep(active);
  const codes = ['key_not_yet_propagated', 'NOT_YET_PROPAGATED'];
  const deadline = Date.now() + 180000;
  let identity;
  do {
    identity = await request('https://api.sylphx.com/v1/whoami', {headers:{authorization:`Bearer ${issued.api_key}`}});
    if (identity.status === 401 && codes.includes(identity.payload?.code) && Date.now() < deadline) await sleep(2000); else break;
  } while (true);
  const who = requireOk(identity, 'Readiness');
  if (issued.key?.status?.principal !== `${who.org}/principals/${who.principal}`) throw Error('Identity mismatch');
  let broker;
  do {
    broker = await request(`https://api.sylphx.com/v1/${env.PROBE_TRUST_POLICY}:exchangeToken`, {method:'POST',headers:{authorization:`Bearer ${issued.api_key}`,'content-type':'application/json'},body:JSON.stringify({repositories:[repository],permissions:{checks:'write'}})});
    if (broker.status === 401 && codes.includes(broker.payload?.code) && Date.now() < deadline) await sleep(2000); else break;
  } while (true);
  const token = requireOk(broker, 'Broker');
  if (token.issuer !== 'github-apps/1299545' || token.credential_kind !== 'access_token' || token.repositories?.length !== 1 || token.repositories[0] !== repository || token.permissions?.checks !== 'write' || Object.entries(token.permissions).some(([k,v]) => k !== 'checks' && v !== 'none' && !(k === 'metadata' && v === 'read'))) throw Error('Unexpected credential scope');
  mask(token.token);
  const identityReply = await request('https://api.github.com/installation/repositories', {headers:{authorization:`Bearer ${token.token}`,accept:'application/vnd.github+json','x-github-api-version':'2022-11-28'}});
  const installationRepositories = requireOk(identityReply, 'Installation repositories');
  if (installationRepositories.total_count !== 1 || installationRepositories.repositories?.[0]?.full_name !== repository) throw Error('Installation repository mismatch');
  console.log(JSON.stringify({at:new Date().toISOString(),issuer:token.issuer,installation_repositories:installationRepositories.repositories.map(r => ({id:r.id,full_name:r.full_name})),permissions:token.permissions}));
  const receipts = [];
  writeFileSync('receipts.json', JSON.stringify({at:new Date().toISOString(),issuer:token.issuer,installation_repositories:installationRepositories},null,2));
  for (const operation of JSON.parse(env.OPERATIONS)) {
    if (!['POST','PATCH'].includes(operation.method) || !/^check-runs(?:\/[0-9]+)?$/.test(operation.path)) throw Error('Invalid operation');
    const url = `https://api.github.com/repos/${repository}/${operation.path}`;
    const at = new Date().toISOString();
    const reply = await request(url, {method:operation.method,headers:{authorization:`Bearer ${token.token}`,accept:'application/vnd.github+json','x-github-api-version':'2022-11-28','content-type':'application/json'},body:JSON.stringify(operation.body)});
    receipts.push({at,method:operation.method,url,body:operation.body,...reply});
    writeFileSync('receipts.json',JSON.stringify(receipts,null,2));
    console.log(JSON.stringify({at,status:reply.status,id:reply.payload.id,check_suite:reply.payload.check_suite,started_at:reply.payload.started_at,completed_at:reply.payload.completed_at}));
    requireOk(reply, 'Check operation');
    if (operation.delay_ms) await sleep(operation.delay_ms);
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
