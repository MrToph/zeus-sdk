const path = require("path");
const fs = require("fs");
const os = require("os");
var toml = require('toml');

var configPath = process.env.DSP_CONFIG_FILE || path.join(os.homedir(), '.dsp', "config.toml");
if (!fs.existsSync(configPath))
  throw new Error(`Config file missing. please copy sample-config.toml to ${configPath}`);

var tomlString = fs.readFileSync(configPath).toString();
var configData;
try {
  configData = toml.parse(tomlString);
}
catch (e) {
  console.error("Parsing error on line " + e.line + ", column " + e.column +
    ": " + e.message);
  throw new Error(`config parse error at ${configPath}`);
}
var globalEnv = {};

const sidechains = configData.sidechains;
// generate nodeos_endpoint in obj
Object.keys(sidechains).forEach(k => {
  const port = sidechains[k].nodeos_port ? ':' + sidechains[k].nodeos_port : '';
  const host = sidechains[k].nodeos_host;
  const prefix = `http${sidechains[k].nodeos_secured ? 's' : ''}://`
  sidechains[k].nodeos_endpoint = prefix + host + port;
})
function createSidechainModels(data) {
  const liquidxMappingsDir = path.resolve(__dirname, `./models/liquidx-mappings/`);
  const localSidechainsDir = path.resolve(__dirname, `./models/local-sidechains/`);
  let sidechains = data.sidechains;
  if (!sidechains) { return; }
  Object.keys(sidechains).forEach(k => {
    let sidechain = sidechains[k];
    let mapping = sidechain.mapping;
    mapping.split(',').forEach(map => {
      let [m1, m2] = map.split(':');
      const mapObj = {
        sidechain_name: sidechain.name,
        mainnet_account: m1,
        chain_account: m2
      }
      if (!fs.existsSync(liquidxMappingsDir)){
        fs.mkdirSync(liquidxMappingsDir);
      }
      fs.writeFileSync(
        `${liquidxMappingsDir}/${sidechain.name}.${m1}.json`,
        JSON.stringify(mapObj, null, 2)
      )
    })
    delete sidechain['mapping'];
    if (!fs.existsSync(localSidechainsDir)){
      fs.mkdirSync(localSidechainsDir);
    }
    fs.writeFileSync(
      path.resolve(`${localSidechainsDir}/${sidechain.name}.json`),
      JSON.stringify(sidechain, null, 2)
      );
  })
}

function parseConfig(data) {
  Object.keys(data).forEach(k => {
    Object.keys(data[k]).forEach(k2 => {
      var envKey = `${k}_${k2}`.toUpperCase();
      globalEnv[envKey] = data[k][k2];
    });
  });
}
createSidechainModels(configData);
parseConfig(configData);
globalEnv = { ...globalEnv, ...process.env };

// Require .env
if (!globalEnv.DSP_ACCOUNT) throw new Error("DSP_ACCOUNT is required");
if (!globalEnv.DSP_PRIVATE_KEY) throw new Error("DSP_PRIVATE_KEY is required");
if (!globalEnv.DATABASE_URL) throw new Error("DATABASE_URL is required");
const DSP_ACCOUNT = globalEnv.DSP_ACCOUNT;
const DSP_PRIVATE_KEY = globalEnv.DSP_PRIVATE_KEY;
const DATABASE_URL = globalEnv.DATABASE_URL;
const DSP_ACCOUNT_PERMISSIONS = globalEnv.DSP_ACCOUNT_PERMISSIONS || 'active';
const DATABASE_NODE_ENV = globalEnv.DATABASE_NODE_ENV || 'production';

// Configure .env
const DSP_PORT = globalEnv.DSP_PORT || 3115;
const IPFS_HOST = globalEnv.IPFS_HOST || 'localhost';
const NODEOS_HOST = globalEnv.NODEOS_HOST || 'localhost';
const NODEOS_PORT = globalEnv.NODEOS_PORT || 8888;
const NODEOS_SECURED = globalEnv.NODEOS_SECURED || 'false'

// Optional .env
const WEBHOOK_DAPP_PORT = globalEnv.WEBHOOK_DAPP_PORT || 8812;
const DEMUX_BACKEND = globalEnv.DEMUX_BACKEND || 'state_history_plugin';
const DEMUX_HEAD_BLOCK = globalEnv.DEMUX_HEAD_BLOCK || 0;
const WEBHOOK_DEMUX_PORT = globalEnv.WEBHOOK_DEMUX_PORT || 3195;
const SOCKET_MODE = globalEnv.DEMUX_SOCKET_MODE || 'sub';
const IPFS_PORT = globalEnv.IPFS_PORT || 5001;
const IPFS_PROTOCOL = globalEnv.IPFS_PROTOCOL || 'http';
const NODEOS_CHAINID = globalEnv.NODEOS_CHAINID || 'aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906';
const NODEOS_WEBSOCKET_PORT = globalEnv.NODEOS_WEBSOCKET_PORT || 8887;

const NODEOS_HOST_DSP = globalEnv.NODEOS_HOST_DSP;
const NODEOS_HOST_DSP_PORT = globalEnv.NODEOS_HOST_DSP_PORT;

// Assert .env
if (['state_history_plugin'].indexOf(DEMUX_BACKEND) === -1) throw new Error("DEMUX_BACKEND must be 'state_history_plugin'");
if (['http', 'https'].indexOf(IPFS_PROTOCOL) === -1) throw new Error("IPFS_PROTOCOL must be either 'http' or 'https'");
if (['true', 'false'].indexOf(NODEOS_SECURED) === -1) throw new Error("NODEOS_SECURED must be either 'true' or 'false'");

const { lstatSync, readdirSync } = fs;
const { join } = require('path');
const isFile = source => !lstatSync(source).isDirectory();

const getFiles = (source, ext) =>
  readdirSync(source).map(name => join(source, name)).filter(isFile).filter(a => a.endsWith(ext)).sort();

const serviceNames = getFiles(path.resolve(__dirname, `./models/dapp-services`), '.json').map(file =>
  JSON.parse(fs.readFileSync(file).toString()).name);

const DSP_SERVICES_ENABLED = globalEnv.DSP_SERVICES_ENABLED || serviceNames.join(',');
const services = DSP_SERVICES_ENABLED.split(',');

const commonEnv = {
  NODEOS_CHAINID,
  NODEOS_HOST,
  NODEOS_PORT,
  NODEOS_SECURED,
  NODEOS_HOST_DSP,
  NODEOS_HOST_DSP_PORT,
  IPFS_HOST,
  IPFS_PORT,
  IPFS_PROTOCOL,
  DSP_ACCOUNT,
  DSP_ACCOUNT_PERMISSIONS,
  DSP_PRIVATE_KEY,
  DSP_PORT,
  DATABASE_URL,
  DATABASE_NODE_ENV
};

const createDSPSidechainServices = (sidechain) => {
  return [
    {
      name: `${sidechain.name}-dapp-services-node`,
      script: path.join(__dirname, 'services', 'dapp-services-node', 'index.js'),
      autorestart: true,
      cwd: __dirname,
      log_date_format: "YYYY-MM-DDTHH:mm:ss",
      env: {
        ...commonEnv,
        PORT: sidechain.dsp_port,
        NODEOS_CHAINID: sidechain.chainid,
        NODEOS_SECURED: sidechain.nodeos_secured,
        NODEOS_HOST: sidechain.nodeos_host,
        NODEOS_PORT: sidechain.nodeos_port,
        DSP_ACCOUNT: sidechain.dsp_account,
        DSP_PRIVATE_KEY: sidechain.dsp_private_key,
        LOGFILE_NAME:`${sidechain.name}-dapp-services-node` 
      }
    },
    {
      name: `${sidechain.name}-demux`,
      script: path.join(__dirname, 'services', 'demux', 'index.js'),
      autorestart: true,
      cwd: __dirname,
      log_date_format: "YYYY-MM-DDTHH:mm:ss",
      env: {
        ...commonEnv,
        NODEOS_CHAINID: sidechain.chainid,
        NODEOS_SECURED: sidechain.nodeos_secured,
        NODEOS_HOST: sidechain.nodeos_host,
        NODEOS_PORT: sidechain.nodeos_port,
        NODEOS_WEBSOCKET_PORT: sidechain.nodeos_state_history_port,
        DEMUX_HEAD_BLOCK: sidechain.demux_head_block,
        PORT: sidechain.demux_port,
        LOGFILE_NAME: `${sidechain.name}-demux`
      }
    }
  ] 
}

const createDSPServiceApp = (name) => ({
  name: `${name}-dapp-service-node`,
  script: path.join(__dirname, 'services', `${name}-dapp-service-node`, 'index.js'),
  autorestart: true,
  cwd: __dirname,
  log_date_format: "YYYY-MM-DDTHH:mm:ss",
  env: {
    ...commonEnv,
    LOGFILE_NAME:`${name}-dapp-service-node` 
  }
});

const servicesApps = services.map(createDSPServiceApp);
// map and flatten
const sidechainServicesApps = Array.prototype.concat.apply(
  [],
  Object.keys(sidechains).map(chain => {
    return createDSPSidechainServices(sidechains[chain])
  })
);
module.exports = {
  force: true,
  apps: [{
      name: 'dapp-services-node',
      script: path.join(__dirname, 'services', 'dapp-services-node', 'index.js'),
      autorestart: true,
      cwd: __dirname,
      log_date_format: "YYYY-MM-DDTHH:mm:ss",
      env: {
        PORT: DSP_PORT,
        WEBHOOK_DAPP_PORT,
        ...commonEnv,
        LOGFILE_NAME: 'dapp-services-node' 
      }
    },
    {
      name: 'demux',
      script: path.join(__dirname, 'services', 'demux', 'index.js'),
      autorestart: true,
      cwd: __dirname,
      log_date_format: "YYYY-MM-DDTHH:mm:ss",
      env: {
        ...commonEnv,
        NODEOS_WEBSOCKET_PORT,
        SOCKET_MODE,
        DEMUX_BACKEND,
        DEMUX_HEAD_BLOCK,
        PORT: WEBHOOK_DEMUX_PORT,
        LOGFILE_NAME: 'demux' 
      }
    },
    ...servicesApps,
    ...sidechainServicesApps
  ]
};
