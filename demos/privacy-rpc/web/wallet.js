import {Wallet, Interface} from '/ethers.js';
const config=await(await fetch('/config')).json();
const $=id=>document.getElementById(id);
let rpcUrl,account,grant;
async function rpc(method,params=[]) {
  const response=await fetch(rpcUrl,{method:'POST',cache:'no-store',referrerPolicy:'no-referrer',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});
  const body=await response.json();if(body.error)throw new Error(body.error.message);return body.result;
}
const run=fn=>async()=>{try{await fn();$('status').textContent='Done';}catch{$('status').textContent='Request failed';}};
$('connect').onclick=run(async()=>{const candidate=new URL($('wallet-url').value);$('wallet-url').value='';if(candidate.origin!==location.origin||!/^\/rpc\/[a-f0-9]{64}$/.test(candidate.pathname))throw new Error('Invalid wallet RPC URL');rpcUrl=candidate.toString();[account]=await rpc('eth_accounts');$('account').textContent=account;});
$('grant').onclick=run(async()=>{const i=Number($('app').value);grant=await rpc('aurora_createReadSession',[{origin:config.apps[i],contracts:[config.tokens[i]],ttlSeconds:300}]);$('grant-url').textContent=grant.rpcUrl;$('open-app').href=config.apps[i];});
$('revoke').onclick=run(async()=>{await rpc('aurora_revokeSession',[grant.rpcUrl]);$('grant-url').textContent='Revoked';});
$('send').onclick=run(async()=>{
  const key=$('key').value;$('key').value='';const wallet=new Wallet(key);
  if(wallet.address.toLowerCase()!==account.toLowerCase())throw new Error('Wrong signer');
  const data=new Interface(['function transfer(address,uint256) returns(bool)']).encodeFunctionData('transfer',[$('recipient').value,BigInt($('amount').value)]);
  const raw=await wallet.signTransaction({type:0,chainId:BigInt(config.chainId),to:config.tokens[Number($('token').value)],data,nonce:Number(await rpc('eth_getTransactionCount',[account,'pending'])),gasPrice:0,gasLimit:2000000,value:0});
  const hash=await rpc('eth_sendRawTransaction',[raw]);$('receipt').textContent=JSON.stringify(await rpc('eth_getTransactionReceipt',[hash]),null,2);
});
