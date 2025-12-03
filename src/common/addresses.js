/**
 * Network address management utilities.
 */

import os from 'os';

export function createAddr(mainAddr, port, addrs) {
  return {
    mainAddr,
    port,
    addrs,
    getMainAddr() {
      return this.mainAddr;
    },
    getPort() {
      return this.port;
    },
    switchMain(index) {
      if (index > this.addrs.length - 1) {
        return null;
      }
      this.mainAddr = this.addrs[index];
      return this.toString();
    },
    toString() {
      return `${this.mainAddr}:${this.port}`;
    },
    network() {
      return 'udp';
    },
    getAddrs() {
      return [...this.addrs];
    },
    forListenerBroadcast() {
      return `:${this.port}`;
    },
    ip() {
      try {
        return this.mainAddr;
      } catch {
        return null;
      }
    },
    ipsV4() {
      return this.addrs.filter(addr => {
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(addr);
      });
    },
    ipsV6() {
      return this.addrs.filter(addr => {
        return addr.includes(':');
      });
    },
    udpAddr() {
      return { host: this.mainAddr, port: this.port };
    },
    mustUDPAddr() {
      return this.udpAddr();
    }
  };
}

export async function getAddresses() {
  const ret = [];
  
  try {
    const interfaces = os.networkInterfaces();
    
    for (const name of Object.keys(interfaces)) {
      const iface = interfaces[name];
      if (!iface) continue;
      
      for (const addr of iface) {
        if (addr.family === 'IPv4' || addr.family === 'IPv6') {
          if (!addr.internal && addr.address) {
            if (!ret.includes(addr.address)) {
              ret.push(addr.address);
            }
          }
        }
      }
    }
  } catch (error) {
    console.error('Error getting addresses:', error);
  }

  if (ret.length === 0) {
    ret.push('127.0.0.1');
  }

  return ret;
}

export async function newAddr(port) {
  const addrs = await getAddresses();
  
  if (addrs.length === 0) {
    throw new Error('no address found');
  }

  return createAddr(addrs[0], port, addrs);
}
