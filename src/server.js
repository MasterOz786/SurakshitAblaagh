/**
 * Main server implementation for Express-based secure tunneling.
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'https';
import { newAddr } from './common/addresses.js';
import { serviceNameSize } from './vars.js';
import crypto from 'crypto';

export function createServerInstance(ctx, port, tlsConfig, cert) {
  const app = express();
  
  app.use(helmet());
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const serverState = {
    ctx,
    addrStruct: null,
    certificate: cert,
    tlsConfig,
    serviceListeners: {},
    incomingSessions: {},
    outgoingSessions: {},
    logger: {
      info: (msg) => console.log(`[INFO] ${msg}`),
      debug: (msg) => console.log(`[DEBUG] ${msg}`),
      error: (msg) => console.error(`[ERROR] ${msg}`)
    }
  };

  return {
    async init() {
      serverState.addrStruct = await newAddr(port);
      serverState.logger.info(`server started on port ${port}`);
      return this;
    },
    getApp() {
      return app;
    },
    getAddrStruct() {
      return serverState.addrStruct;
    },
    getCertificate() {
      return serverState.certificate;
    },
    getLogger() {
      return serverState.logger;
    },
    newListener(name) {
      const hash = crypto.createHash('blake2b512').update(name).digest();
      const key = hash.slice(0, serviceNameSize).toString('hex');

      if (serverState.serviceListeners[key]) {
        throw new Error('a listener with the same name is already registered');
      }

      const listener = {
        name,
        server: this,
        connQueue: []
      };

      serverState.serviceListeners[key] = listener;
      return listener;
    },
    getTarget(stream) {
      const checkBuff = stream.read(serviceNameSize);
      if (!checkBuff || checkBuff.length !== serviceNameSize) {
        return null;
      }
      return checkBuff.toString('hex');
    },
    close() {
      Object.values(serverState.serviceListeners).forEach(listener => {
        listener.close && listener.close();
      });
      Object.values(serverState.incomingSessions).forEach(session => {
        session.close && session.close();
      });
      Object.values(serverState.outgoingSessions).forEach(session => {
        session.close && session.close();
      });
    },
    getCtx() {
      return serverState.ctx;
    }
  };
}

export function getBaseTLSConfig(host, cert) {
  return {
    key: cert.getKeyPEM(),
    cert: cert.getCertPEM(),
    requestCert: true,
    rejectUnauthorized: true
  };
}

export function newHTTPEchoServer(ln) {
  const app = express();
  app.use(express.json());
  return app;
}

