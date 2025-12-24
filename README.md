# Cosmos AWS KMS Signer

A TypeScript library for signing and sending Cosmos blockchain transactions using AWS Key Management Service (KMS). This implementation supports Celestia and other Cosmos-based chains.

## Features

- 🔐 **AWS KMS Integration**: Sign transactions using AWS KMS asymmetric keys (secp256k1)
- 🌌 **Cosmos SDK Compatible**: Works with any Cosmos-based blockchain
- 📦 **TypeScript**: Fully typed with TypeScript
- 🔒 **Secure**: Private keys never leave AWS KMS
- ⚡ **Low-s Normalization**: Implements Cosmos SDK signature requirements

## Prerequisites

- Node.js 18+ and pnpm
- AWS account with KMS access
- An AWS KMS asymmetric key (secp256k1) for signing
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)

## Installation

```bash
pnpm install
```

## Usage

### Basic Example

```typescript
import { CosmosKmsSigner } from './cosmos-txs.js';

const signer = new CosmosKmsSigner('your-kms-key-id', 'us-west-2');

await signer.sendTia(
  'https://rpc-mocha.pops.one',
  'celestia10kw22p0jx5jhnky2erymda9f2h5lehlpr0mjef',
  BigInt(1100) // or '1100' as string
);
```

### Constructor Parameters

- `kmsKeyId` (required): Your AWS KMS key ID or ARN
- `region` (optional): AWS region (defaults to `'us-west-2'`)

### Method: `sendTia()`

Sends TIA tokens to a specified address.

**Parameters:**
- `celestiaRpcUrl` (string): RPC endpoint URL for the Celestia network
- `toAddress` (string): Recipient address (Bech32 format)
- `sendAmount` (bigint | string): Amount to send in utia (smallest unit)

**Returns:** Promise that resolves when the transaction is broadcast

## AWS KMS Setup

1. **Create an asymmetric KMS key:**
   ```bash
   aws kms create-key \
     --key-spec ECC_SECG_P256K1 \
     --key-usage SIGN_VERIFY
   ```

2. **Get the public key:**
   ```bash
   aws kms get-public-key --key-id <your-key-id>
   ```

3. **Configure IAM permissions:**
   - `kms:GetPublicKey`
   - `kms:Sign`

## How It Works

1. **Public Key Retrieval**: Fetches the public key from AWS KMS and parses the DER-encoded format
2. **Address Derivation**: Derives the Cosmos address from the compressed public key using SHA256 and RIPEMD160
3. **Transaction Building**: Constructs a Cosmos transaction with proper message encoding
4. **Signing**: Signs the transaction using AWS KMS with ECDSA_SHA_256
5. **Signature Normalization**: Converts DER signature to Cosmos format with low-s normalization
6. **Broadcasting**: Broadcasts the signed transaction to the network

## Technical Details

### Signature Format

The library handles the conversion from AWS KMS DER-encoded signatures to the 64-byte Cosmos format (R || S), with automatic low-s normalization to prevent signature malleability.

### Supported Chains

While designed for Celestia, this library can be adapted for other Cosmos-based chains by modifying the `denom` and address prefix.

## Development

### Run Tests

```bash
pnpm test
```

### Project Structure

- `cosmos-txs.ts`: Main implementation with `CosmosKmsSigner` class
- `test.ts`: Example usage and test file
- `package.json`: Dependencies and scripts

## Dependencies

- `@aws-sdk/client-kms`: AWS KMS client
- `@cosmjs/*`: Cosmos SDK JavaScript libraries
- `@estos/asn1ts`: ASN.1 parsing for DER signatures
- `cosmjs-types`: TypeScript types for Cosmos messages

## License

ISC

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- [Cosmos SDK Documentation](https://docs.cosmos.network/)
- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [CosmJS Documentation](https://github.com/cosmos/cosmjs)

