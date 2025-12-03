/**
 * Node token generation and parsing for temporary certificates.
 */

// Base91 encoding implementation (pure JavaScript)
function base91Encode(data) {
  const base91Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
  let result = '';
  let b = 0;
  let n = 0;
  
  for (let i = 0; i < data.length; i++) {
    b |= data[i] << n;
    n += 8;
    
    if (n > 13) {
      let v = b & 8191;
      if (v > 88) {
        b >>= 13;
        n -= 13;
      } else {
        v = b & 16383;
        b >>= 14;
        n -= 14;
      }
      result += base91Chars[v % 91];
      result += base91Chars[Math.floor(v / 91)];
    }
  }
  
  if (n !== 0) {
    result += base91Chars[b % 91];
    if (n > 7 || b > 90) {
      result += base91Chars[Math.floor(b / 91)];
    }
  }
  
  return result;
}

function base91Decode(str) {
  const base91Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"';
  const lookup = {};
  for (let i = 0; i < base91Chars.length; i++) {
    lookup[base91Chars[i]] = i;
  }
  
  let b = 0;
  let n = 0;
  let v = -1;
  const result = [];
  
  for (let i = 0; i < str.length; i++) {
    const c = lookup[str[i]];
    if (c === undefined) continue;
    
    if (v < 0) {
      v = c;
    } else {
      v += c * 91;
      b |= v << n;
      n += (v & 8191) > 88 ? 13 : 14;
      
      do {
        result.push(b & 0xff);
        b >>= 8;
        n -= 8;
      } while (n > 7);
      
      v = -1;
    }
  }
  
  if (v + 1) {
    result.push((b | (v << n)) & 0xff);
  }
  
  return new Uint8Array(result);
}
import { unmarshal, newDefaultCertificationConfigWithDefaultTemplate } from './certificate.js';

export async function getToken(server) {
  const certConfig = newDefaultCertificationConfigWithDefaultTemplate('TOKEN');
  certConfig.lifeTime = 5 * 60 * 1000; // 5 minutes
  const tmpCert = server.getCertificate().newCert(certConfig, 'TOKEN');

  const tokenObj = {
    A: {
      mainAddr: server.getAddrStruct().getMainAddr(),
      port: server.getAddrStruct().getPort(),
      addrs: server.getAddrStruct().getAddrs()
    },
    C: tmpCert.marshal().toString('hex')
  };

  const asJSON = JSON.stringify(tokenObj);
  const compressed = Buffer.from(asJSON).toString('base64'); // Simple compression placeholder
  return base91Encode(compressed);
}

export async function readToken(tokenString) {
  const { createAddr } = await import('./common/addresses.js');
  const { unmarshal } = await import('./certificate.js');
  
  const compressed = base91Decode(tokenString);
  const asJSON = Buffer.from(compressed, 'base64').toString();
  const tokenObj = JSON.parse(asJSON);

  const addrData = tokenObj.A;
  const addr = createAddr(
    addrData.mainAddr,
    addrData.port,
    addrData.addrs
  );

  const certBytes = Buffer.from(tokenObj.C, 'hex');
  const certificate = unmarshal(certBytes);

  return { addr, certificate };
}

