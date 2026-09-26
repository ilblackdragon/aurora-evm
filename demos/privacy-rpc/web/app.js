import {privateProvider} from './sdk.js';
const settings = await (await fetch('/config')).json();
const $ = id => document.getElementById(id);
$('title').textContent = settings.name;
const token = settings.tokens[settings.tokenIndex];
let provider, account, events = [], historyFlight, duringHistory;
const word = address => address.slice(2).toLowerCase().padStart(64, '0');
const eventKey = e => `${e.blockHash}:${e.transactionHash}:${e.logIndex}`;
function render() { $('events').textContent = JSON.stringify(events, null, 2); }
function clear() { $('status').textContent='Disconnected'; $('account').textContent=''; $('balance').textContent='—'; events=[]; render(); }
async function refresh() {
  const current=provider;
  const balance = await current.request({method:'eth_call',params:[{to:token,data:'0x70a08231'+word(account)},'latest']});
  if(provider===current) $('balance').textContent = BigInt(balance).toString();
}
function apply(rows,event) {
  const next=rows.filter(v=>eventKey(v)!==eventKey(event));
  if(!event.removed) next.push(event);
  return next;
}
async function history() {
  if(historyFlight) return historyFlight;
  const current=provider,buffer=[];duringHistory=buffer;
  const flight=(async()=>{
    let rows=await current.request({method:'eth_getLogs',params:[{address:token,fromBlock:'earliest',toBlock:'latest'}]});
    for(const event of buffer) rows=apply(rows,event);
    if(provider===current){events=rows;render();}
  })();
  historyFlight=flight;
  try {await flight;} finally {if(historyFlight===flight)historyFlight=undefined;if(duringHistory===buffer)duringHistory=undefined;}
}
async function connect() {
  const url=$('rpc-url').value; $('rpc-url').value='';
  const previous=provider;provider=undefined;account=undefined;historyFlight=undefined;duringHistory=undefined;previous?.close();clear();
  const current=privateProvider(url);provider=current;
  [account]=await current.request({method:'eth_accounts'});
  $('account').textContent=account;
  await refresh();
  await current.subscribe({address:token}, e=> {
    if(provider!==current)return;
    duringHistory?.push(e);events=apply(events,e);render();refresh().catch(()=>{});
  },()=>{if(provider===current){provider=undefined;account=undefined;clear();$('status').textContent='Session ended';}});
  await history();
  $('status').textContent='Connected';
}
const run = fn => async () => {try {await fn();} catch {clear();$('status').textContent='Access unavailable';}};
$('connect').onclick=run(connect);$('refresh').onclick=run(refresh);$('history').onclick=run(history);
$('disconnect').onclick=()=>{provider?.close();provider=undefined;account=undefined;clear();};
// Browser E2E tests exercise exactly the same transport as the UI.
window.demo={request:args=>provider.request(args),events:()=>structuredClone(events),historyLoading:()=>Boolean(historyFlight)};
