import * as _ from 'lodash';

import {
  AuthType,
  AddressHashMode,
  PubKeyEncoding,
  RECOVERABLE_ECDSA_SIG_LENGTH_BYTES,
  SingleSigHashMode,
  MultiSigHashMode,
} from './constants';

import { BufferArray, txidFromData, sha512_256, leftPadHex } from './utils';

import { Address, addressFromPublicKeys, addressFromVersionHash } from './types';

import {
  StacksPublicKey,
  StacksPrivateKey,
  createStacksPublicKey,
  isCompressed,
  signWithKey,
  getPublicKey,
} from './keys';

import * as BigNum from 'bn.js';
import { BufferReader } from './bufferReader';
import { SerializationError, NotImplementedError, DeserializationError } from './errors';
import { Buffer } from 'buffer';

abstract class Deserializable {
  abstract serialize(): Buffer;
  abstract deserialize(bufferReader: BufferReader): void;
  static deserialize<T extends Deserializable>(this: new () => T, bufferReader: BufferReader): T {
    const message = new this();
    message.deserialize(bufferReader);
    return message;
  }
}

export class MessageSignature extends Deserializable {
  signature?: string;

  constructor(signature?: string) {
    super();
    if (signature) {
      const length = Buffer.from(signature, 'hex').byteLength;
      if (length != RECOVERABLE_ECDSA_SIG_LENGTH_BYTES) {
        throw Error('Invalid signature');
      }
    }
    this.signature = signature;
  }

  static empty(): MessageSignature {
    const messageSignature = new this();
    messageSignature.signature = Buffer.alloc(RECOVERABLE_ECDSA_SIG_LENGTH_BYTES, 0x00).toString(
      'hex'
    );
    return messageSignature;
  }

  toString(): string {
    return this.signature ?? '';
  }

  serialize(): Buffer {
    const bufferArray: BufferArray = new BufferArray();
    if (this.signature === undefined) {
      throw new SerializationError('"signature" is undefined');
    }
    bufferArray.appendHexString(this.signature);
    return bufferArray.concatBuffer();
  }

  deserialize(bufferReader: BufferReader) {
    this.signature = bufferReader.readBuffer(RECOVERABLE_ECDSA_SIG_LENGTH_BYTES).toString('hex');
  }
}

type TransactionAuthField = StacksPublicKey | MessageSignature;

export interface SingleSigSpendingCondition {
  hashMode: SingleSigHashMode;
  signer: Address;
  nonce: BigNum;
  fee: BigNum;
  keyEncoding: PubKeyEncoding;
  signature: MessageSignature;
}

export interface MultiSigSpendingCondition {
  hashMode: MultiSigHashMode;
  signer: Address;
  nonce: BigNum;
  fee: BigNum;
  fields: TransactionAuthField[];
  signaturesRequired: number;
}

export type SpendingCondition = SingleSigSpendingCondition | MultiSigSpendingCondition;

export function createSingleSigSpendingCondition(
  hashMode: SingleSigHashMode,
  pubKey: string,
  nonce: BigNum,
  fee: BigNum
): SingleSigSpendingCondition {
  const signer = addressFromPublicKeys(0, hashMode, 1, [createStacksPublicKey(pubKey)]);
  const keyEncoding = isCompressed(createStacksPublicKey(pubKey))
    ? PubKeyEncoding.Compressed
    : PubKeyEncoding.Uncompressed;

  return {
    hashMode,
    signer,
    nonce,
    fee,
    keyEncoding,
    signature: MessageSignature.empty(),
  };
}

function isSingleSig(condition: SpendingCondition) {
  return 'signature' in condition;
}

function clearCondition(condition: SpendingCondition): SpendingCondition {
  const cloned = _.cloneDeep(condition);
  cloned.nonce = new BigNum(0);
  cloned.fee = new BigNum(0);

  if (isSingleSig(cloned)) {
    (cloned as SingleSigSpendingCondition).signature = MessageSignature.empty();
  } else {
    (cloned as MultiSigSpendingCondition).fields = [];
  }

  return cloned;
}

export function serializeSingleSigSpendingCondition(condition: SingleSigSpendingCondition): Buffer {
  const bufferArray: BufferArray = new BufferArray();
  bufferArray.appendByte(condition.hashMode);
  bufferArray.appendHexString(condition.signer.hash160);
  bufferArray.push(condition.nonce.toArrayLike(Buffer, 'be', 8));
  bufferArray.push(condition.fee.toArrayLike(Buffer, 'be', 8));
  bufferArray.appendByte(condition.keyEncoding);
  bufferArray.push(condition.signature.serialize());
  return bufferArray.concatBuffer();
}

export function serializeMultiSigSpendingCondition(condition: MultiSigSpendingCondition): Buffer {
  //TODO: unimplemented
  return Buffer.from('');
}

export function deserializeSingleSigSpendingCondition(
  hashMode: SingleSigHashMode,
  bufferReader: BufferReader
): SingleSigSpendingCondition {
  const signerPubKeyHash = bufferReader.readBuffer(20).toString('hex');
  const signer = addressFromVersionHash(0, signerPubKeyHash);
  const nonce = new BigNum(bufferReader.readBuffer(8).toString('hex'), 16);
  const fee = new BigNum(bufferReader.readBuffer(8).toString('hex'), 16);

  const keyEncoding = bufferReader.readUInt8Enum(PubKeyEncoding, n => {
    throw new DeserializationError(`Could not parse ${n} as PubKeyEncoding`);
  });
  const signature = MessageSignature.deserialize(bufferReader);

  return {
    hashMode,
    signer,
    nonce,
    fee,
    keyEncoding,
    signature,
  };
}

export function deserializeMultiSigSpendingCondition(
  hashMode: MultiSigHashMode,
  bufferReader: BufferReader
): MultiSigSpendingCondition {
  //TODO: unimplemented
  throw new NotImplementedError('multi sig deserialization');
}

export function serializeSpendingCondition(condition: SpendingCondition): Buffer {
  if (isSingleSig(condition)) {
    return serializeSingleSigSpendingCondition(condition as SingleSigSpendingCondition);
  } else {
    return serializeMultiSigSpendingCondition(condition as MultiSigSpendingCondition);
  }
}

export function deserializeSpendingCondition(bufferReader: BufferReader): SpendingCondition {
  const hashMode = bufferReader.readUInt8Enum(AddressHashMode, n => {
    throw new DeserializationError(`Could not parse ${n} as AddressHashMode`);
  });

  if (hashMode === AddressHashMode.SerializeP2PKH || hashMode === AddressHashMode.SerializeP2WPKH) {
    return deserializeSingleSigSpendingCondition(hashMode, bufferReader);
  } else {
    return deserializeMultiSigSpendingCondition(hashMode, bufferReader);
  }
}

export function makeSigHashPreSign(
  curSigHash: string,
  authType: AuthType,
  fee: BigNum,
  nonce: BigNum
): string {
  // new hash combines the previous hash and all the new data this signature will add. This
  // includes:
  // * the previous hash
  // * the auth flag
  // * the tx fee (big-endian 8-byte number)
  // * nonce (big-endian 8-byte number)
  const hashLength = 32 + 1 + 8 + 8;

  const sigHash =
    curSigHash +
    Buffer.from([authType]).toString('hex') +
    fee.toArrayLike(Buffer, 'be', 8).toString('hex') +
    nonce.toArrayLike(Buffer, 'be', 8).toString('hex');

  if (Buffer.from(sigHash, 'hex').byteLength !== hashLength) {
    throw Error('Invalid signature hash length');
  }

  return txidFromData(Buffer.from(sigHash, 'hex'));
}

function makeSigHashPostSign(
  curSigHash: string,
  publicKey: StacksPublicKey,
  signature: MessageSignature
): string {
  // new hash combines the previous hash and all the new data this signature will add.  This
  // includes:
  // * the public key compression flag
  // * the signature
  const hashLength = 32 + 1 + RECOVERABLE_ECDSA_SIG_LENGTH_BYTES;
  const pubKeyEncoding = isCompressed(publicKey)
    ? PubKeyEncoding.Compressed
    : PubKeyEncoding.Uncompressed;

  const sigHash = curSigHash + leftPadHex(pubKeyEncoding.toString(16)) + signature.toString();

  if (Buffer.from(sigHash, 'hex').byteLength > hashLength) {
    throw Error('Invalid signature hash length');
  }

  return new sha512_256().update(sigHash).digest('hex');
}

export function nextSignature(
  curSigHash: string,
  authType: AuthType,
  fee: BigNum,
  nonce: BigNum,
  privateKey: StacksPrivateKey
): {
  nextSig: MessageSignature;
  nextSigHash: string;
} {
  const sigHashPreSign = makeSigHashPreSign(curSigHash, authType, fee, nonce);
  const signature = signWithKey(privateKey, sigHashPreSign);
  const publicKey = getPublicKey(privateKey);
  const nextSigHash = makeSigHashPostSign(sigHashPreSign, publicKey, signature);

  return {
    nextSig: signature,
    nextSigHash,
  };
}

export class Authorization extends Deserializable {
  authType?: AuthType;
  spendingCondition?: SpendingCondition;

  constructor(authType?: AuthType, spendingConditions?: SpendingCondition) {
    super();
    this.authType = authType;
    this.spendingCondition = spendingConditions;
  }

  intoInitialSighashAuth(): Authorization {
    if (this.spendingCondition) {
      if (this.authType === AuthType.Standard) {
        return new Authorization(AuthType.Standard, clearCondition(this.spendingCondition));
      } else {
        return new Authorization(AuthType.Sponsored, clearCondition(this.spendingCondition));
      }
    }

    throw new Error('Authorization missing SpendingCondition');
  }

  setFee(amount: BigNum) {
    this.spendingCondition!.fee = amount;
  }

  setNonce(nonce: BigNum) {
    this.spendingCondition!.nonce = nonce;
  }

  serialize(): Buffer {
    const bufferArray: BufferArray = new BufferArray();
    if (this.authType === undefined) {
      throw new SerializationError('"authType" is undefined');
    }
    bufferArray.appendByte(this.authType);

    switch (this.authType) {
      case AuthType.Standard:
        if (this.spendingCondition === undefined) {
          throw new SerializationError('"spendingCondition" is undefined');
        }
        bufferArray.push(serializeSpendingCondition(this.spendingCondition));
        break;
      case AuthType.Sponsored:
        // TODO
        throw new SerializationError('Not yet implemented: serializing sponsored transactions');
      default:
        throw new SerializationError(
          `Unexpected transaction AuthType while serializing: ${this.authType}`
        );
    }

    return bufferArray.concatBuffer();
  }

  deserialize(bufferReader: BufferReader) {
    this.authType = bufferReader.readUInt8Enum(AuthType, n => {
      throw new DeserializationError(`Could not parse ${n} as AuthType`);
    });

    switch (this.authType) {
      case AuthType.Standard:
        this.spendingCondition = deserializeSpendingCondition(bufferReader);
        break;
      case AuthType.Sponsored:
        // TODO
        throw new DeserializationError('Not yet implemented: deserializing sponsored transactions');
      default:
        throw new DeserializationError(
          `Unexpected transaction AuthType while deserializing: ${this.authType}`
        );
    }
  }
}

export class StandardAuthorization extends Authorization {
  constructor(spendingCondition: SpendingCondition) {
    super(AuthType.Standard, spendingCondition);
  }
}

export class SponsoredAuthorization extends Authorization {
  constructor(spendingCondition: SpendingCondition) {
    super(AuthType.Sponsored, spendingCondition);
  }
}
