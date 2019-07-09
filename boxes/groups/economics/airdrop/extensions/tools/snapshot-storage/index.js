var s3StorageHandler = require('./s3').default;
var { loadModels } = require('../models');
var format = require('./format').default;
var { getEos } = require('../eos/utils');

// factory
export default async function(args) {
    var model = (await loadModels('airdrops')).find(a => a.name === args['name']);
    var handler = new s3StorageHandler(args, model);
    var eos = await getEos(null, args.network ?  args : undefined);

    return {
        model,
        handler,
        format,
        eos
    }
}
