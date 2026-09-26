// EIP-1193-shaped read transport. Credentials stay in memory, never in browser URLs,
// localStorage, analytics, or error messages. It does not grant transaction authority.
export function privateProvider(rpcUrl) {
  const url = new URL(rpcUrl);
  if (url.hostname !== '127.0.0.1' || url.protocol !== 'http:' || !/^\/rpc\/[a-f0-9]{64}$/.test(url.pathname))
    throw new Error('Use an app RPC URL from the local wallet');
  let active = true, socket, sequence = 0;
  return {
    async request({method, params = []}) {
      if (!active) throw new Error('Session closed');
      const response = await fetch(url, {method:'POST', credentials:'omit', cache:'no-store', referrerPolicy:'no-referrer',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({jsonrpc:'2.0', id:++sequence, method, params})});
      const result = await response.json();
      if (!active) throw new Error('Session closed');
      if (result.error) throw Object.assign(new Error(result.error.message), {code:result.error.code});
      return result.result;
    },
    subscribe(filter, onEvent, onClose) {
      if (!active) return Promise.reject(new Error('Session closed'));
      socket = new WebSocket(url.toString().replace('http:', 'ws:') + '/ws');
      return new Promise((resolve, reject) => {
        let subscribed = false;
        socket.onopen = () => socket.send(JSON.stringify({jsonrpc:'2.0',id:1,method:'eth_subscribe',params:['logs',filter]}));
        socket.onmessage = message => {
          const data = JSON.parse(message.data);
          if (data.error) { reject(new Error(data.error.message)); socket.close(); }
          else if (data.method === 'eth_subscription') onEvent(data.params.result);
          else { subscribed = true; resolve(data.result); }
        };
        socket.onerror = () => reject(new Error('Private connection unavailable'));
        socket.onclose = () => { active = false; if (!subscribed) reject(new Error('Session closed')); onClose(); };
      });
    },
    close() { active = false; socket?.close(); }
  };
}
