import {test,expect} from '@playwright/test';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,rm,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {Wallet,Interface} from 'ethers';
const tokenAbi=new Interface(['function balanceOf(address) view returns(uint256)','function transfer(address,uint256) returns(bool)','function approve(address,uint256) returns(bool)']);
const forwardAbi=new Interface(['function pretend(address,address) view returns(uint256)']);
const batchAbi=new Interface(['function pay(address,address,address,uint256,uint256)']);
let server,dir,config;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function rpc(url,method,params=[],origin) {
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json',...(origin?{origin}:{})},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
  return response.json();
}
async function ok(url,method,params=[],origin) {
  const result=await rpc(url,method,params,origin);expect(result.error).toBeUndefined();return result.result;
}
async function grant(user,app,options={}) {
  return ok(config.users[user].rpcUrl,'aurora_createReadSession',[{origin:config.public.apps[app],contracts:[config.public.tokens[app]],ttlSeconds:300,...options}]);
}
function balanceCall(token,owner,extra={}) {return {to:token,data:tokenAbi.encodeFunctionData('balanceOf',[owner]),...extra};}
async function raw(user,to,data,overrides={}) {
  const account=config.users[user];
  const nonce=Number(await ok(account.rpcUrl,'eth_getTransactionCount',[account.address,'pending']));
  return new Wallet(account.privateKey).signTransaction({type:0,chainId:BigInt(config.public.chainId),to,data,nonce,gasLimit:2000000,gasPrice:0,value:0,...overrides});
}
async function send(user,to,data) {
  return ok(config.users[user].rpcUrl,'eth_sendRawTransaction',[await raw(user,to,data)]);
}
async function connect(browser,user,app,session) {
  const context=await browser.newContext();const page=await context.newPage();
  await page.goto(config.public.apps[app]);await page.locator('#rpc-url').fill(session.rpcUrl);await page.locator('#connect').click();
  await expect(page.locator('#status')).toHaveText('Connected');
  await expect(page.locator('#account')).toHaveText(config.users[user].address);
  return page;
}
async function browserRpc(page,method,params) {
  return page.evaluate(async({method,params})=>{try{return {result:await window.demo.request({method,params})};}catch(e){return {error:e.code};}},{method,params});
}
test.beforeEach(async()=>{
  dir=await mkdtemp(join(tmpdir(),'aurora-private-rpc-'));const path=join(dir,'credentials.json');
  server=spawn('./target/debug/aurora-privacy-rpc-demo',['--credentials',path,'--test-controls'],{env:{...process.env,PORT:'0',APP_A_PORT:'0',APP_B_PORT:'0'},stdio:['ignore','pipe','pipe']});
  let errors='';server.stderr.on('data',d=>errors+=d.toString());
  for(let n=0;n<200;n++){
    if(server.exitCode!==null)throw new Error('Demo failed: '+errors);
    try {config=JSON.parse(await readFile(path,'utf8'));await fetch(config.baseUrl+'/config');break;}catch{await pause(50);}
  }
  if(!config)throw new Error('Demo did not start');
  expect((await stat(path)).mode&0o777).toBe(0o600);
});
test.afterEach(async()=>{server?.kill('SIGTERM');config=undefined;await rm(dir,{recursive:true,force:true});});

test('two users and two web apps: scoped reads, real wallet transfer, subscriptions and nested-call isolation',async({browser})=>{
  const sessions=await Promise.all([grant('alice',0),grant('alice',1),grant('bob',0),grant('bob',1)]);
  const pages=await Promise.all([connect(browser,'alice',0,sessions[0]),connect(browser,'alice',1,sessions[1]),connect(browser,'bob',0,sessions[2]),connect(browser,'bob',1,sessions[3])]);
  for(const page of pages)await expect(page.locator('#balance')).toHaveText('1000');
  const bob=config.users.bob.address,alice=config.users.alice.address,[a,b]=config.public.tokens;
  expect((await browserRpc(pages[2],'eth_call',[balanceCall(a,alice),'latest'])).error).toBe(4100);
  expect((await browserRpc(pages[2],'eth_call',[balanceCall(a,alice,{from:alice}),'latest'])).error).toBe(4100);
  expect((await browserRpc(pages[2],'eth_call',[balanceCall(b,bob),'latest'])).error).toBe(4100);
  const probe=token=>({to:config.public.forwarder,data:forwardAbi.encodeFunctionData('pretend',[token,bob])});
  expect(BigInt((await browserRpc(pages[2],'eth_call',[probe(a),'latest'])).result)).toBe(1000n);
  expect((await browserRpc(pages[2],'eth_call',[probe(b),'latest'])).error).toBe(4100);
  // A website from another browser origin cannot use this app URL.
  expect((await rpc(sessions[2].rpcUrl,'eth_accounts',[],config.public.apps[1])).error.code).toBe(4100);
  const crossApp=await pages[3].evaluate(async url=>{
    try {await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_accounts',params:[]})});return 'allowed';}
    catch {return 'blocked';}
  },sessions[2].rpcUrl);
  expect(crossApp).toBe('blocked');
  expect((await browserRpc(pages[2],'eth_getTransactionCount',[bob,'latest'])).error).toBe(4100);
  // It remains a bearer credential: a non-browser with the secret can forge Origin.
  expect(await ok(sessions[2].rpcUrl,'eth_accounts',[],config.public.apps[0])).toEqual([bob]);
  expect((await rpc(config.baseUrl+'/rpc','eth_call',[balanceCall(a,bob),'latest'])).error.code).toBe(4100);
  // Exercise the actual browser wallet signing path, not an unsigned server faucet.
  const wallet=await browser.newPage();await wallet.goto(config.baseUrl);
  await wallet.locator('#wallet-url').fill(config.users.alice.rpcUrl);await wallet.locator('#connect').click();
  await expect(wallet.locator('#account')).toHaveText(alice);
  await wallet.locator('#key').fill(config.users.alice.privateKey);await wallet.locator('#recipient').fill(bob);
  await wallet.locator('#amount').fill('10');await wallet.locator('#send').click();
  await expect(wallet.locator('#receipt')).toContainText('"status": "0x1"');
  await expect(pages[0].locator('#balance')).toHaveText('990');await expect(pages[2].locator('#balance')).toHaveText('1010');
  await expect(pages[1].locator('#balance')).toHaveText('1000');await expect(pages[3].locator('#balance')).toHaveText('1000');
  expect(await pages[2].evaluate(()=>window.demo.events().length)).toBe(1);
  expect(await pages[3].evaluate(()=>window.demo.events().length)).toBe(0);
  // Query state never advances the user's transaction nonce.
  expect(await ok(config.users.bob.rpcUrl,'eth_getTransactionCount',[bob,'pending'])).toBe('0x0');
  const tx=await raw('alice',a,tokenAbi.encodeFunctionData('transfer',[bob,1]));
  expect((await rpc(sessions[0].rpcUrl,'eth_sendRawTransaction',[tx],config.public.apps[0])).error.code).toBe(4100);
  expect((await rpc(config.users.bob.rpcUrl,'eth_sendRawTransaction',[tx])).error.code).toBe(4100);
  const hash=await ok(config.users.alice.rpcUrl,'eth_sendRawTransaction',[tx]);expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
  expect((await rpc(config.users.alice.rpcUrl,'eth_sendRawTransaction',[tx])).error.code).toBe(4100);
  const wrongChain=await raw('alice',a,tokenAbi.encodeFunctionData('transfer',[bob,1]),{chainId:1});
  expect((await rpc(config.users.alice.rpcUrl,'eth_sendRawTransaction',[wrongChain])).error.code).toBe(4100);
  // Batch requests do not share caller overrides or leak one identity into another.
  const response=await fetch(sessions[2].rpcUrl,{method:'POST',headers:{'content-type':'application/json',origin:config.public.apps[0]},body:JSON.stringify([
    {jsonrpc:'2.0',id:1,method:'eth_call',params:[balanceCall(a,alice,{from:alice}),'latest']},
    {jsonrpc:'2.0',id:2,method:'eth_call',params:[balanceCall(a,bob),'latest']},
  ])});const results=await response.json();expect(results[0].error.code).toBe(4100);expect(BigInt(results[1].result)).toBe(1011n);
});

test('offline receipt discovery, per-log authorization, filtered pagination and failed-transaction rollback',async({browser})=>{
  const alice=config.users.alice.address,bob=config.users.bob.address,token=config.public.tokens[0],batch=config.public.batch;
  const approval=await send('alice',token,tokenAbi.encodeFunctionData('approve',[batch,100]));
  // One transaction: Bob's payment plus a payment to a contract. Bob may see only his log.
  const tx=await send('alice',batch,batchAbi.encodeFunctionData('pay',[token,bob,batch,10,7]));
  const aliceSession=await grant('alice',0),bobSession=await grant('bob',0);
  const bobPage=await connect(browser,'bob',0,bobSession);
  await expect(bobPage.locator('#balance')).toHaveText('1010');
  expect(await bobPage.evaluate(()=>window.demo.events().length)).toBe(1);
  const bobReceipt=await ok(bobSession.rpcUrl,'eth_getTransactionReceipt',[tx],config.public.apps[0]);
  expect(bobReceipt.privacyView).toBe(true);expect(bobReceipt.logs).toHaveLength(1);
  expect(bobReceipt).not.toHaveProperty('input');expect(bobReceipt).not.toHaveProperty('logsBloom');
  const aliceReceipt=await ok(aliceSession.rpcUrl,'eth_getTransactionReceipt',[tx],config.public.apps[0]);expect(aliceReceipt.logs).toHaveLength(2);
  expect((await rpc(bobSession.rpcUrl,'eth_getTransactionReceipt',[approval],config.public.apps[0])).error.code).toBe(4100);
  for(const method of ['debug_traceTransaction','eth_getTransactionByHash','eth_getStorageAt','eth_getProof'])
    expect((await rpc(bobSession.rpcUrl,method,[tx],config.public.apps[0])).error.code).toBe(-32601);
  const bobEvents=await ok(bobSession.rpcUrl,'aurora_getEvents',[{limit:1}],config.public.apps[0]);
  expect(bobEvents.events).toHaveLength(1);expect(bobEvents.hasMore).toBe(false);expect(bobEvents.nextCursor).toBeNull();
  const aliceEvents=await ok(aliceSession.rpcUrl,'aurora_getEvents',[{limit:1}],config.public.apps[0]);expect(aliceEvents.hasMore).toBe(true);
  expect((await rpc(bobSession.rpcUrl,'aurora_getEvents',[{limit:1,cursor:aliceEvents.nextCursor}],config.public.apps[0])).error.code).toBe(4100);
  const recent=await grant('bob',0,{historyFrom:3});expect(await ok(recent.rpcUrl,'eth_getLogs',[{}],config.public.apps[0])).toEqual([]);
  // The first transfer executes, the second fails; neither its state nor its log survives.
  const failed=await send('alice',batch,batchAbi.encodeFunctionData('pay',[token,bob,batch,1,99999]));
  expect((await ok(config.users.alice.rpcUrl,'eth_getTransactionReceipt',[failed])).status).toBe('0x0');
  expect((await ok(config.users.alice.rpcUrl,'eth_getTransactionReceipt',[failed])).logs).toEqual([]);
  await bobPage.locator('#refresh').click();await expect(bobPage.locator('#balance')).toHaveText('1010');
  expect(await ok(bobSession.rpcUrl,'eth_getLogs',[{}],config.public.apps[0])).toHaveLength(1);
  const callerNonce=await ok(config.users.alice.rpcUrl,'eth_getTransactionCount',[alice,'pending']);
  expect((await rpc(aliceSession.rpcUrl,'eth_call',[{to:token,data:tokenAbi.encodeFunctionData('transfer',[bob,1])},'latest'],config.public.apps[0])).error.code).toBe(4100);
  expect(await ok(config.users.alice.rpcUrl,'eth_getTransactionCount',[alice,'pending'])).toBe(callerNonce);
});

test('revocation, expiry, URL rotation and reorgs remove live views and invalidate cursors',async({browser})=>{
  const token=config.public.tokens[0],bob=config.users.bob.address;
  const session=await grant('bob',0);const page=await connect(browser,'bob',0,session);
  const tx=await send('alice',token,tokenAbi.encodeFunctionData('transfer',[bob,5]));
  await expect(page.locator('#balance')).toHaveText('1005');
  await send('alice',token,tokenAbi.encodeFunctionData('transfer',[bob,5]));
  await expect(page.locator('#balance')).toHaveText('1010');
  const cursor=await ok(session.rpcUrl,'aurora_getEvents',[{limit:1}],config.public.apps[0]);expect(cursor.hasMore).toBe(true);
  // Hold a historical response from before the reorg; the live tombstone must
  // also be applied when that older response eventually reaches the browser.
  let releaseHistory,historyCaptured;
  const hold=new Promise(resolve=>releaseHistory=resolve);
  const captured=new Promise(resolve=>historyCaptured=resolve);
  await page.route(session.rpcUrl,async route=>{
    if(route.request().postDataJSON().method==='eth_getLogs'){
      const response=await route.fetch();historyCaptured();await hold;await route.fulfill({response});
    } else await route.continue();
  });
  await page.locator('#history').click();await captured;
  expect((await fetch(config.operatorUrl,{method:'POST'})).status).toBe(200);
  await expect(page.locator('#balance')).toHaveText('1005');
  releaseHistory();await expect.poll(()=>page.evaluate(()=>window.demo.historyLoading())).toBe(false);
  await page.unroute(session.rpcUrl);
  await expect.poll(()=>page.evaluate(()=>window.demo.events().length)).toBe(1);
  expect((await rpc(session.rpcUrl,'aurora_getEvents',[{limit:1,cursor:cursor.nextCursor}],config.public.apps[0])).error.code).toBe(4100);
  expect((await fetch(config.operatorUrl,{method:'POST'})).status).toBe(200);
  await expect(page.locator('#balance')).toHaveText('1000');await expect.poll(()=>page.evaluate(()=>window.demo.events().length)).toBe(0);
  expect((await rpc(session.rpcUrl,'eth_getTransactionReceipt',[tx],config.public.apps[0])).error.code).toBe(4100);
  await ok(config.users.bob.rpcUrl,'aurora_revokeSession',[session.rpcUrl]);
  await expect(page.locator('#status')).toHaveText('Session ended');await expect(page.locator('#balance')).toHaveText('—');
  expect((await rpc(session.rpcUrl,'eth_accounts',[],config.public.apps[0])).error.code).toBe(4100);
  const expires=await grant('bob',1,{ttlSeconds:5});const expiresPage=await connect(browser,'bob',1,expires);
  await expect(expiresPage.locator('#status')).toHaveText('Session ended',{timeout:10000});
  expect((await rpc(expires.rpcUrl,'eth_accounts',[],config.public.apps[1])).error.code).toBe(4100);
  const active=await grant('bob',0);const oldRoot=config.users.bob.rpcUrl;
  const rotated=await ok(oldRoot,'aurora_rotateWalletUrl');
  expect((await rpc(oldRoot,'eth_accounts')).error.code).toBe(4100);
  expect((await rpc(active.rpcUrl,'eth_accounts',[],config.public.apps[0])).error.code).toBe(4100);
  expect(await ok(rotated.rpcUrl,'eth_accounts')).toEqual([bob]);
});
