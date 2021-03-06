const { getCreateKeys } = require('../../helpers/key-utils');
const getDefaultArgs = require('../../helpers/getDefaultArgs');
const { getEos } = require('./utils');

const { loadModels } = require('../models');
const fetch = require('node-fetch');

const dappServicesContract = process.env.DAPPSERVICES_CONTRACT || 'dappservices';
const dappServicesLiquidXContract = process.env.DAPPSERVICES_LIQUIDX_CONTRACT || 'liquidx';


const testProvidersList = ['pprovider1', 'pprovider2'];

function getContractAccountFor(model, sidechain = null) {
  if (sidechain) {
    const mapEntry = (loadModels('liquidx-mappings')).find(m => m.sidechain_name === sidechain.name && m.mainnet_account === model.contract);
    if (!mapEntry)
      throw new Error('mapping not found')
    return mapEntry.chain_account;
  }
  var envName = process.env[`DAPPSERVICES_CONTRACT_${model.name.toUpperCase()}`];
  return envName || model.contract;
}
async function genAllocateDAPPTokens(deployedContract, serviceName, provider = '', selectedPackage = 'default', sidechain = null, updConsumerAuth = true) {
  var providers = testProvidersList;
  if (provider !== '') {
    providers = [provider];
  }
  for (var i = 0; i < providers.length; i++) {
    var currentProvider = providers[i];

    await genAllocateDAPPTokensInner(deployedContract, serviceName, provider = currentProvider, (currentProvider == "pprovider2" && selectedPackage == 'default') ? 'foobar' : selectedPackage, sidechain, providers, updConsumerAuth);
  }

}

async function genAllocateDAPPTokensInner(deployedContract, serviceName, provider = 'pprovider1', selectedPackage = 'default', sidechain = null, providers = ['pprovider1'], updConsumerAuth) {
  var key = await getCreateKeys(dappServicesContract, null, false, sidechain);
  var model = (await loadModels('dapp-services')).find(m => m.name == serviceName);
  var service = getContractAccountFor(model);

  var contract = deployedContract.address;
  var eos = await getEos(contract, null, sidechain);
  let servicesTokenContract = await eos.contract(dappServicesContract);
  await servicesTokenContract.issue({
    to: contract,
    quantity: '1000.0000 DAPP',
    memo: `${provider}`
  }, {
    authorization: `${dappServicesContract}@active`,
    keyProvider: [key.active.privateKey]
  });

  await servicesTokenContract.selectpkg({
    owner: contract,
    provider,
    service,
    'package': selectedPackage
  }, {
    authorization: `${contract}@active`,
  });
  await servicesTokenContract.stake({
    from: contract,
    service,
    provider,
    quantity: '500.0000 DAPP'
  }, {
    authorization: `${contract}@active`,
  });

  // for testing backwards compatibility
  if (!updConsumerAuth) { return; }

  let auth = providers.map(p=>{
    return {
      permission: { actor: p, permission: 'active' },
      weight: 1,
    }
  });

  await (await eos.contract('eosio')).updateauth({
    account: contract,
    permission: 'dsp',
    parent: 'active',
    auth: {
      threshold: 1,
      keys: [],
      accounts: auth,
      waits: []
    }
  }, { authorization: `${contract}@active` });

  try {
    var commandNames = Object.keys(model.commands);
    await Promise.all(commandNames.map(async(command) => {
      await (await eos.contract('eosio')).linkauth({
        account: contract,
        code: contract,
        type: `x${command}`,
        requirement: 'dsp'
      }, { authorization: `${contract}@active` });
    }));
  } catch(e) {}  
}

function postData(url = ``, data = {}) {
  // Default options are marked with *
  return fetch(url, {
      method: 'POST', // *GET, POST, PUT, DELETE, etc.
      mode: 'cors', // no-cors, cors, *same-origin
      cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
      credentials: 'same-origin', // include, *same-origin, omit
      headers: {
        // "Content-Type": "application/json",
        // "Content-Type": "application/x-www-form-urlencoded",
      },
      redirect: 'follow', // manual, *follow, error
      referrer: 'no-referrer', // no-referrer, *client
      body: JSON.stringify(data) // body data type must match "Content-Type" header
    })
    .then(response => response.json()); // parses response to JSON
}


const getEndpointForContract = ({
  payer,
  service,
  sidechain
}) => {
  if (sidechain) {
    // resolve sidechain

    return `http://localhost:${sidechain.dsp_port}`;
  }
  return "http://localhost:13015";
};

const readVRAMData = async({
  contract,
  key,
  table,
  scope,
  keytype,
  keysize,
  sidechain
}) => {
  const service = "ipfsservice1";
  const endpoint = getEndpointForContract({ payer: contract, service, sidechain });
  const result = await postData(`${endpoint}/v1/dsp/${service}/get_table_row`, {
    contract,
    scope,
    table,
    key,
    keytype,
    keysize
  });
  if (result.error) {
    throw new Error(result.error);
  }
  return result;
};

const createLiquidXMapping = async(sidechain_name, mainnet_account, chain_account, oneway) => {
  const mapEntry = (loadModels('liquidx-mappings')).find(m => m.sidechain_name === sidechain_name && m.mainnet_account === "dappservices");
  if (!mapEntry)
    throw new Error('mapping not found')
  const dappservicex = mapEntry.chain_account;
  var sidechain = (await loadModels('local-sidechains')).find(m => m.name == sidechain_name);
  const eos = await getEos(chain_account, null, sidechain);
  let sisterChainDappServices = await eos.contract(dappservicex);
  await sisterChainDappServices.setlink({
    owner: chain_account,
    mainnet_owner: mainnet_account,
  }, { authorization: `${chain_account}@active` });
  if (!oneway) {
    var eosMain = await getEos(mainnet_account);
    let liquidXInstance = await eosMain.contract(dappServicesLiquidXContract);
    await liquidXInstance.addaccount({
      owner: mainnet_account,
      chain_account,
      chain_name: sidechain_name
    }, { authorization: `${mainnet_account}@active` });
  }

}
module.exports = { genAllocateDAPPTokens, dappServicesContract, getContractAccountFor, readVRAMData, getEndpointForContract, testProvidersList, dappServicesLiquidXContract, createLiquidXMapping };
