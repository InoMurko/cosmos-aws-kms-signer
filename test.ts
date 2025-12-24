import { CosmosKmsSigner } from './cosmos-txs.js';

async function test() {
  const kmsKeyId = '1c4c9477-2c47-456a-929e-97a62a9dc124';
  const celestiaRpcUrl = 'https://rpc-mocha.pops.one';
  const bmAddress = 'celestia10kw22p0jx5jhnky2erymda9f2h5lehlpr0mjef';
  const sendAmount = BigInt(110);

  console.log('Initializing CosmosKmsSigner...');
  const signer = new CosmosKmsSigner(kmsKeyId);

  try {
    console.log('Sending TIA transaction...');
    await signer.sendTia(celestiaRpcUrl, bmAddress, sendAmount);
    console.log('Test completed successfully!');
  } catch (error) {
    console.error('Test failed:', error);
    process.exit(1);
  }
}

test();

