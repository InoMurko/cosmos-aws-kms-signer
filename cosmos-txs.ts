import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import { ripemd160, sha256 } from '@cosmjs/crypto';
import { toBech32 } from '@cosmjs/encoding';
import { makeSignDoc } from '@cosmjs/proto-signing';
import { StargateClient } from '@cosmjs/stargate';
import * as asn1ts from '@estos/asn1ts';
import { MsgSend } from 'cosmjs-types/cosmos/bank/v1beta1/tx.js';
import { PubKey } from 'cosmjs-types/cosmos/crypto/secp256k1/keys.js';
import { SignMode } from 'cosmjs-types/cosmos/tx/signing/v1beta1/signing.js';
import {
  AuthInfo,
  Fee,
  SignerInfo,
  TxBody,
  TxRaw,
} from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import { Any } from 'cosmjs-types/google/protobuf/any.js';

// secp256k1 curve order (N) - the order of the base point
// This is the constant for secp256k1 curve (used by Bitcoin/Ethereum/Cosmos)
const SECP256K1_ORDER = BigInt(
  '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
);

// Half of the curve order
// Equivalent to: new(big.Int).Rsh(p256Order, 1)
const SECP256K1_HALF_ORDER = SECP256K1_ORDER >> BigInt(1);

export class CosmosKmsSigner {
  private readonly kmsClient: KMSClient;
  private readonly kmsKeyId: string;
  private readonly denom: string = 'utia';

  constructor(kmsKeyId: string, region: string = 'us-west-2') {
    this.kmsKeyId = kmsKeyId;
    this.kmsClient = new KMSClient({ region });
  }

  /**
   * Parse DER-encoded ECDSA signature using ASN1.ts and extract r, s values
   */
  private parseDerSignature(der: Uint8Array): { r: Uint8Array; s: Uint8Array } {
    // Define the schema for ECDSA signature: SEQUENCE { INTEGER, INTEGER }
    const schema = new asn1ts.Sequence({
      name: 'ECDSASignature',
      value: [
        new asn1ts.Integer({ name: 'r' }),
        new asn1ts.Integer({ name: 's' }),
      ],
    });

    // Verify and parse the DER data against the schema
    // Convert Uint8Array to ArrayBuffer for verifySchema
    const arrayBuffer = der.buffer instanceof ArrayBuffer 
      ? der.buffer 
      : new Uint8Array(der).buffer;
    const result = asn1ts.verifySchema(arrayBuffer, schema);
    if (!result.verified || !result.result) {
      throw new Error('Invalid DER signature: failed to parse');
    }

    // Extract r and s integers
    const rInt = result.result.getTypedValueByName(asn1ts.Integer, 'r');
    const sInt = result.result.getTypedValueByName(asn1ts.Integer, 's');

    if (!rInt || !sInt) {
      throw new Error('Invalid DER signature: missing r or s');
    }

    // Get the raw bytes from the integers
    let r = new Uint8Array(rInt.valueBlock.valueHexView);
    let s = new Uint8Array(sInt.valueBlock.valueHexView);

    // Remove leading zero bytes (used for positive sign in DER)
    if (r.length > 32 && r[0] === 0x00) {
      r = r.slice(1);
    }
    if (s.length > 32 && s[0] === 0x00) {
      s = s.slice(1);
    }

    return { r, s };
  }

  /**
   * Converts a BigInt to a fixed-width big-endian byte array
   */
  private numberToBytesBE(num: bigint, length: number): Uint8Array {
    const hex = num.toString(16).padStart(length * 2, '0');
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  /**
   * Converts a big-endian byte array to BigInt
   */
  private bytesToNumberBE(bytes: Uint8Array): bigint {
    let result = BigInt(0);
    for (const byte of bytes) {
      result = (result << BigInt(8)) | BigInt(byte);
    }
    return result;
  }

  /**
   * Checks if sigS is normalized (falls in the lower half of the curve order)
   * Equivalent to: IsSNormalized(sigS *big.Int) bool
   */
  private isSNormalized(sigS: bigint): boolean {
    return sigS <= SECP256K1_HALF_ORDER;
  }

  /**
   * Normalizes the s value to the lower half of the curve order
   * This prevents signature malleability
   * Equivalent to: NormalizeS(sigS *big.Int) *big.Int
   */
  private normalizeS(sigS: bigint): bigint {
    if (this.isSNormalized(sigS)) {
      return sigS;
    }
    return SECP256K1_ORDER - sigS;
  }

  /**
   * Serializes signature to R || S format
   * R and S are padded to 32 bytes each (64 bytes total)
   * Equivalent to: signatureRaw(r, s *big.Int) []byte
   */
  private signatureRaw(r: bigint, s: bigint): Uint8Array {
    const rBytes = this.numberToBytesBE(r, 32);
    const sBytes = this.numberToBytesBE(s, 32);
    const sigBytes = new Uint8Array(64);
    sigBytes.set(rBytes, 0);
    sigBytes.set(sBytes, 32);
    return sigBytes;
  }

  /**
   * Convert DER signature to 64-byte Cosmos signature
   * Cosmos SDK requires low-s normalized signatures (s must be <= n/2)
   * See: https://github.com/cosmos/cosmos-sdk/blob/main/crypto/keys/internal/ecdsa/pubkey.go
   * See: https://github.com/cosmos/cosmos-sdk/blob/main/crypto/keys/internal/ecdsa/privkey.go
   */
  private derToCosmosSig(der: Uint8Array): Uint8Array {
    const { r, s } = this.parseDerSignature(der);

    // Convert r and s bytes to BigInt
    const rBigInt = this.bytesToNumberBE(r);
    const sBigInt = this.bytesToNumberBE(s);

    // Normalize s to the lower half of the curve order
    const normS = this.normalizeS(sBigInt);

    // Serialize as R || S (64 bytes)
    return this.signatureRaw(rBigInt, normS);
  }

  /**
   * Get compressed public key from KMS using ASN1.ts to parse DER
   */
  private async getPublicKeyFromKMS(): Promise<Uint8Array> {
    const command = new GetPublicKeyCommand({ KeyId: this.kmsKeyId });
    const response = await this.kmsClient.send(command);

    if (!response.PublicKey) {
      throw new Error('Failed to get public key from KMS');
    }

    // KMS returns DER-encoded SubjectPublicKeyInfo structure:
    // SEQUENCE {
    //   SEQUENCE { OID, OID }  -- algorithm identifier
    //   BIT STRING             -- public key bytes
    // }
    const derKey = new Uint8Array(response.PublicKey);

    // Define schema for SubjectPublicKeyInfo
    const schema = new asn1ts.Sequence({
      name: 'SubjectPublicKeyInfo',
      value: [
        new asn1ts.Sequence({
          name: 'algorithm',
          value: [
            new asn1ts.ObjectIdentifier({ name: 'algorithmId' }),
            new asn1ts.ObjectIdentifier({ name: 'parameters' }),
          ],
        }),
        new asn1ts.BitString({ name: 'publicKey' }),
      ],
    });

    // Convert Uint8Array to ArrayBuffer for verifySchema
    const arrayBuffer = derKey.buffer instanceof ArrayBuffer 
      ? derKey.buffer 
      : new Uint8Array(derKey).buffer;
    const result = asn1ts.verifySchema(arrayBuffer, schema);
    if (!result.verified || !result.result) {
      throw new Error('Failed to parse public key DER structure');
    }

    const bitString = result.result.getTypedValueByName(
      asn1ts.BitString,
      'publicKey',
    );
    if (!bitString) {
      throw new Error('Public key not found in DER structure');
    }

    // The bit string contains the uncompressed public key (65 bytes: 04 + x + y)
    const uncompressedKey = new Uint8Array(bitString.valueBlock.valueHexView);

    if (uncompressedKey.length !== 65 || uncompressedKey[0] !== 0x04) {
      throw new Error(
        `Invalid uncompressed public key format: length=${uncompressedKey.length}, prefix=${uncompressedKey[0]}`,
      );
    }

    // Extract x and y coordinates
    const x = uncompressedKey.slice(1, 33);
    const y = uncompressedKey.slice(33, 65);

    // Compress the public key: prefix (02 for even y, 03 for odd y) + x coordinate
    // y is guaranteed to be 32 bytes (indices 0-31) since uncompressedKey is validated to be 65 bytes
    const prefix = (y[31]! & 1) === 0 ? 0x02 : 0x03;

    const compressedKey = new Uint8Array(33);
    compressedKey[0] = prefix;
    compressedKey.set(x, 1);

    return compressedKey;
  }

  /**
   * Derive Celestia address from compressed public key
   */
  private pubkeyToAddress(pubkey: Uint8Array): string {
    const hash = ripemd160(sha256(pubkey));
    return toBech32('celestia', hash);
  }

  /**
   * Sign with KMS
   */
  private async signWithKMS(message: Uint8Array): Promise<Uint8Array> {
    // Hash the message with SHA256 (Cosmos uses SHA256 for signing)
    const digest = sha256(message);

    const command = new SignCommand({
      KeyId: this.kmsKeyId,
      Message: digest,
      MessageType: 'DIGEST',
      SigningAlgorithm: 'ECDSA_SHA_256',
    });

    const response = await this.kmsClient.send(command);

    if (!response.Signature) {
      throw new Error('Failed to sign with KMS');
    }

    // Convert DER signature to Cosmos format
    return this.derToCosmosSig(new Uint8Array(response.Signature));
  }

  /**
   * Send TIA tokens using AWS KMS for signing
   */
  async sendTia(
    celestiaRpcUrl: string,
    toAddress: string,
    sendAmount: bigint | string,
  ) {
    // Get public key and derive address
    const pubkey = await this.getPublicKeyFromKMS();
    const senderAddress = this.pubkeyToAddress(pubkey);
    console.log(`Sender address: ${senderAddress}`);

    // Connect to Celestia RPC
    const client = await StargateClient.connect(celestiaRpcUrl);
    const chainId = await client.getChainId();
    console.log(`Chain ID: ${chainId}`);
    // Get account info for sequence and account number
    const account = await client.getAccount(senderAddress);
    if (!account) {
      throw new Error(`Account ${senderAddress} not found on chain`);
    }
    console.log(
      `Account number: ${account.accountNumber}, Sequence: ${account.sequence}`,
    );

    // Amount to send
    const amountString = typeof sendAmount === 'bigint' ? sendAmount.toString() : sendAmount;
    console.log(`Sending ${amountString} ${this.denom} to ${toAddress}`);

    // Build the MsgSend
    const msgSend = MsgSend.fromPartial({
      fromAddress: senderAddress,
      toAddress: toAddress,
      amount: [{ denom: this.denom, amount: amountString }],
    });

    const msgAny = Any.fromPartial({
      typeUrl: '/cosmos.bank.v1beta1.MsgSend',
      value: MsgSend.encode(msgSend).finish(),
    });

    // Build TxBody
    const txBody = TxBody.fromPartial({
      messages: [msgAny],
      memo: 'Sent via AWS KMS',
    });
    const txBodyBytes = TxBody.encode(txBody).finish();

    // Build AuthInfo
    const pubkeyAny = Any.fromPartial({
      typeUrl: '/cosmos.crypto.secp256k1.PubKey',
      value: PubKey.encode({ key: pubkey }).finish(),
    });

    const signerInfo = SignerInfo.fromPartial({
      publicKey: pubkeyAny,
      modeInfo: {
        single: { mode: SignMode.SIGN_MODE_DIRECT },
      },
      sequence: BigInt(account.sequence),
    });

    // Calculate fee: gasLimit * gasPrice
    // Minimum gas price is 0.004 TIA per gas unit
    // Using 0.005 TIA per gas for safety margin
    const gasPrice = 0.005; // TIA per gas unit
    const gasLimit = BigInt(200000);
    const feeAmount = Math.ceil(Number(gasLimit) * gasPrice).toString();

    console.log(
      `Fee calculation: gasLimit=${gasLimit}, gasPrice=${gasPrice} TIA/gas, feeAmount=${feeAmount} ${this.denom}`,
    );

    const fee = Fee.fromPartial({
      amount: [{ denom: this.denom, amount: feeAmount }],
      gasLimit: gasLimit,
    });
    const authInfo = AuthInfo.fromPartial({
      signerInfos: [signerInfo],
      fee: fee,
    });
    const authInfoBytes = AuthInfo.encode(authInfo).finish();

    // Create SignDoc and sign
    const signDoc = makeSignDoc(
      txBodyBytes,
      authInfoBytes,
      chainId,
      account.accountNumber,
    );

    // Serialize SignDoc for signing
    const { SignDoc } = await import('cosmjs-types/cosmos/tx/v1beta1/tx.js');
    const signDocBytes = SignDoc.encode(signDoc).finish();

    // Sign with KMS
    const signature = await this.signWithKMS(signDocBytes);

    // Build the signed transaction
    const txRaw = TxRaw.fromPartial({
      bodyBytes: txBodyBytes,
      authInfoBytes: authInfoBytes,
      signatures: [signature],
    });

    const txBytes = TxRaw.encode(txRaw).finish();

    // Broadcast
    console.log('sending...');
    const result = await client.broadcastTx(txBytes);

    console.log(`Transaction successful!`);
    console.log(`Transaction hash: ${result.transactionHash}`);
    console.log(`Height: ${result.height}`);

    client.disconnect();
  }
}
