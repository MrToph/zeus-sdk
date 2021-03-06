var path = require('path');
var os = require('os');
var fs = require('fs');
var { execPromise } = require('../../helpers/_exec');
var temp = require('temp');
var AWS = require('aws-sdk');
var sha256 = require('js-sha256').sha256;
const { promisify } = require('util');
const mkdir = promisify(temp.mkdir); // (A)
temp.track();

function walk(dir) {
  var results = [];
  var list = fs.readdirSync(dir, { withFileTypes: true });
  list.forEach(function (dirent) {
    var file = dir + '/' + dirent.name;
    results.push({ path: file, isDirectory: dirent.isDirectory() });
    if (dirent.isDirectory()) {
      results = results.concat(walk(file));
    }
  });
  return results;
}

// Setup process exit/crash handler to always cleanup temp
const cleanup = function () {
  temp.cleanupSync();
};
['exit', 'SIGINT', 'uncaughtException'].map(sig => process.on(sig, cleanup));


module.exports = {
  description: 'installs a templated plugin or a seed, without writing in deps',
  builder: (yargs) => {
    return yargs.option('type', {
      // describe: '',
      default: 'local'
    }).option('invalidate', {
      // describe: '',
      default: true
    }).option('bucket', {
      // describe: '',
      default: 'liquidapps.artifacts'
    }).option('prefix', {
      // describe: '',
      default: 'boxes/'
    }).option('update-mapping', {
      // describe: '',
      default: true
    }).option('moddate', {
      // describe: '',
      default: false
    }).example('$0 deploy box');
  },
  command: 'box',
  handler: async (args) => {
    // resolve github system boxes
    // throw new Error('only ipfs is currently supported');
    // var repo = boxName.split('/')[0];
    // var repo = boxName.split('/')[1];
    var stagingPath = await mkdir('zeus');
    const packageName = path.resolve('.').split(path.sep).pop();

    let stdout;
    var inputPath = path.resolve('.');

    console.log(`staging in ${stagingPath}`);
    var zeusBoxJsonPath = path.join(inputPath, 'zeus-box.json');
    if (!fs.existsSync(zeusBoxJsonPath)) {
      temp.cleanupSync();
      throw new Error('zeus-box.json not found');
    }
    var zeusBoxJson = JSON.parse(fs.readFileSync(zeusBoxJsonPath));

    var ignoreList = [];
    if (zeusBoxJson.ignore) { ignoreList = zeusBoxJson.ignore.filter(a => a != 'zeus-box.json').map(a => a); }

    if (fs.existsSync('.gitignore') && !args.noIgnore) {
      ignoreList = [...ignoreList, ...fs.readFileSync('.gitignore').toString().split('\n').filter(a => a.trim() != '')];
    }
    ignoreList = [...ignoreList, '.git'];
    // copy to dest
    stdout = await execPromise(`${process.env.RSYNC || 'rsync'} -a ${path.join(inputPath)} ${stagingPath} ${ignoreList.map(a => `--exclude ${a}`).join(' ')}`, {
      cwd: path.resolve('.')
    });

    // load zeus-box.json
    const hooks = zeusBoxJson.hooks;

    // run build script
    if (hooks && hooks['post-stage']) {
      console.log('running post stage');
      stdout = await execPromise(hooks['post-stage'], {
        cwd: stagingPath
      });
    }

    if (args.moddate) {
      var files = await walk(stagingPath);

      for (var file of files) {
        // As git does not store directories, it will not be able to set the moddate in step.sh
        if (file.isDirectory) {
          await execPromise(`touch -d "2019-10-01 12:00:00" ${file.path}`);
        }

        let localPath = file.path.replace(stagingPath, '.');
        stdout = await execPromise(`${process.env.ZIP || 'zip'} -X ./box.zip ${localPath}`, { cwd: stagingPath });
      }
    } else {
      stdout = await execPromise(`${process.env.ZIP || 'zip'} -X -r ./box.zip .`, { cwd: stagingPath });
    }

    var uri = '';
    var hash;
    switch (args.type) {
      case 'ipfs':
        var ipfsout = await execPromise(`${process.env.IPFS || 'ipfs'} add ./box.zip`, { cwd: stagingPath });
        hash = ipfsout.split(' ')[1];
        uri = `ipfs://${hash}`;
        break;
      case 's3':
        args.invalidate = false;
        const s3 = new AWS.S3({ apiVersion: '2006-03-01' });
        var data = fs.readFileSync(path.join(stagingPath, './box.zip'));
        hash = sha256(data);

        var binaryData = new Buffer(data, 'binary');
        if (args.bucket.length == 0) { throw new Error('must pass bucket when uploading to S3'); }
        const s3Key = `${args.prefix}${hash}.zip`;
        const res = await s3.putObject({
          Bucket: args.bucket,
          Key: s3Key,
          ACL: 'public-read',
          Body: binaryData
        }).promise();
        uri = `https://s3.us-east-2.amazonaws.com/${args.bucket}/${s3Key}`;
        break;
      case 'local':
      default:
        const packagePath = path.join(args.storagePath, args.prefix, packageName);
        await execPromise(`mkdir -p ${packagePath}`);
        await execPromise(`cp ./box.zip ${packagePath}/`, { cwd: stagingPath });
        uri = `file://${packagePath}/box.zip`;
    }

    console.log(`box deployed to ${uri}`);
    // run post script

    // invalidate endpoints:
    if (args.type === 'ipfs' && args.invalidate && process.env.SKIP_IPFS_GATEWAY !== 'true') {
      console.log('invalidating ipfs...');
      var urls = [`https://ipfs.io/ipfs/${hash}`, `https://cloudflare-ipfs.com/ipfs/${hash}`, `https://ipfs.io/ipfs/${hash}`, `https://cloudflare-ipfs.com/ipfs/${hash}`];
      await Promise.race(urls.map(url => execPromise(`${process.env.CURL || 'curl'} --silent --output /dev/null ${url}`, {})));
    }

    // console.log('cleaning up');
    temp.cleanupSync();
    // var archive = `https://github.com/${}/${}/archive/master.zip`;
    // https://github.com/zeit/serve/archive/master.zip
    if (args['update-mapping']) {
      console.log('updating local mapping', packageName);

      var mappingFile = path.resolve(__dirname, '../../mapping.js');
      var boxes = require('../../mapping');
      boxes[packageName] = uri;
      fs.writeFileSync(path.resolve(mappingFile), `module.exports = ${JSON.stringify(boxes, null, 2)};`);
    }
    console.log('done.');
    process.exit();
    // resolve github 3rd party boxes
    // resolve ipfs boxes
    // resolve "onchain" boxes
  }
};
