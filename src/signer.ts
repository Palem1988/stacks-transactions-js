import { StacksTransaction } from './transaction';
import { StacksPrivateKey } from './keys';
import * as _ from 'lodash';
import { SpendingCondition } from './authorization';
import { AuthType } from './constants';
import { SigningError } from './errors';

export class TransactionSigner {
  transaction: StacksTransaction;
  sigHash: string;
  originDone: boolean;
  checkOversign: boolean;
  checkOverlap: boolean;

  constructor(transaction: StacksTransaction) {
    this.transaction = transaction;
    this.sigHash = transaction.signBegin();
    this.originDone = false;
    this.checkOversign = true;
    this.checkOverlap = true;
  }

  static createSponsorSigner(transaction: StacksTransaction, spendingCondition: SpendingCondition) {
    if (transaction.auth.authType != AuthType.Sponsored) {
      throw new SigningError('Cannot add sponsor to non-sponsored transaction');
    }

    const tx: StacksTransaction = _.cloneDeep(transaction);
    tx.setSponsor(spendingCondition);
    const originSigHash = tx.verifyOrigin();
    const signer = new this(tx);
    signer.originDone = true;
    signer.sigHash = originSigHash;
    signer.checkOversign = true;
    signer.checkOverlap = true;
    return signer;
  }

  signOrigin(privateKey: StacksPrivateKey) {
    if (this.checkOverlap && this.originDone) {
      throw new SigningError('Cannot sign origin after sponsor key');
    }

    if (this.transaction.auth === undefined) {
      throw new SigningError('"transaction.auth" is undefined');
    }
    if (this.transaction.auth.spendingCondition === undefined) {
      throw new SigningError('"transaction.auth.spendingCondition" is undefined');
    }
    if (this.transaction.auth.spendingCondition.signaturesRequired === undefined) {
      throw new SigningError(
        '"transaction.auth.spendingCondition.signaturesRequired" is undefined'
      );
    }

    if (
      this.checkOversign &&
      this.transaction.auth.spendingCondition.numSignatures() >=
        this.transaction.auth.spendingCondition.signaturesRequired
    ) {
      throw new SigningError('Origin would have too many signatures');
    }

    const nextSighash = this.transaction.signNextOrigin(this.sigHash, privateKey);
    this.sigHash = nextSighash;
  }

  signSponsor(privateKey: StacksPrivateKey) {
    if (this.transaction.auth === undefined) {
      throw new SigningError('"transaction.auth" is undefined');
    }
    if (this.transaction.auth.sponsorSpendingCondition === undefined) {
      throw new SigningError('"transaction.auth.spendingCondition" is undefined');
    }
    if (this.transaction.auth.sponsorSpendingCondition.signaturesRequired === undefined) {
      throw new SigningError(
        '"transaction.auth.spendingCondition.signaturesRequired" is undefined'
      );
    }

    if (
      this.checkOversign &&
      this.transaction.auth.sponsorSpendingCondition.numSignatures() >=
        this.transaction.auth.sponsorSpendingCondition.signaturesRequired
    ) {
      throw new SigningError('Sponsor would have too many signatures');
    }

    const nextSighash = this.transaction.signNextSponsor(this.sigHash, privateKey);
    this.sigHash = nextSighash;
    this.originDone = true;
  }

  getTxInComplete(): StacksTransaction {
    return _.cloneDeep(this.transaction);
  }

  resume(transaction: StacksTransaction) {
    this.transaction = _.cloneDeep(transaction);
    this.sigHash = transaction.signBegin();
  }
}
