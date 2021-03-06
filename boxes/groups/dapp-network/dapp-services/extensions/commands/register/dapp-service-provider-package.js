const { emojMap, execPromise } = require('../../helpers/_exec');
var { loadModels } = require('../../tools/models');
var { getEos } = require('../../tools/eos/utils');
var generateModel = (commandNames, cost_per_action = 1) => {
  var model = {};
  commandNames.forEach(a => {
    model[`${a}_model_field`] = {
      cost_per_action
    };
  });
  return model;
};
var cmd = 'dapp-service-provider-package';
module.exports = {
  description: 'register a new DAPP service provider package',
  builder: (yargs) => {
    yargs.option('key', {
      describe: 'active private key for DSP'
    }).option('api-endpoint', {
      describe: 'DSP API endpoint'
    }).option('package-json-uri', {
      describe: 'DSP Package JSON URI'
    }).option('min-unstake-period', {
      describe: 'Minimum Unstake period',
      default: 60 * 60
    }).option('package-period', {
      describe: 'Package Period',
      default: 60 * 60 * 24
    }).option('quota', {
      describe: 'Package Quota',
      type: 'string',
      default: '10.0000'
    }).option('price-per-action', {
      describe: 'Milli-QUOTA per service action',
      default: 1
    }).option('min-stake-quantity', {
      describe: 'Minimum Stake',
      type: 'string',
      default: '10.0000'
    }).option('dappservices-contract', {
      describe: 'dappservices contract account (only for testing)',
      default: 'dappservices'
    }).option('service-contract', {
      describe: 'service contract account (only for testing)'
    }).option('network', {
      describe: 'network to work on',
      default: 'development'
    }).demandOption(['key', 'api-endpoint', 'package-json-uri']);
  },
  command: `${cmd} <service> <provider> <package-id>`,
  handler: async(args) => {
    var key = args.key;
    var models = await loadModels('dapp-services');
    var serviceModel = models.find(a => a.name == args['service']);
    if (!serviceModel) { throw new Error('service not found: ' + args['service']); }
    var serviceContract = args['service-contract'] || serviceModel.contract;
    var eos = await getEos(null, args);
    var contractInstance = await eos.contract(args['dappservices-contract']);
    console.log(emojMap.zap + `registering package:${args['package-id']}`);
    try {
      await contractInstance.regpkg({
        newpackage: {
          id: 0,
          provider: args['provider'],
          api_endpoint: args['api-endpoint'],
          package_json_uri: args['package-json-uri'],
          enabled: false,
          service: serviceContract,
          package_id: args['package-id'],
          quota: `${args['quota']} QUOTA`,
          min_stake_quantity: `${args['min-stake-quantity']} DAPP`,
          min_unstake_period: args['min-unstake-period'],
          package_period: args['package-period']
        }
      }, {
        authorization: `${args['provider']}@active`,
        broadcast: true,
        sign: true,
        keyProvider: [key]
      });

      contractInstance = await eos.contract(serviceContract);
      await contractInstance.regprovider({
        provider: args['provider'],
        model: {
          package_id: args['package-id'],
          model: generateModel(Object.keys(serviceModel.commands), args['price-per-action'])
        }
      }, {
        authorization: `${args['provider']}@active`,
        broadcast: true,
        sign: true,
        keyProvider: [key]
      });
    }
    catch (e) {
      console.log(emojMap.white_frowning_face + 'failed', e);
      return;
    }
    console.log(emojMap.ok + `package:${args['package-id']} registered successfully`);
  }
};
