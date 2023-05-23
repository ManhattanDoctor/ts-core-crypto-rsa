import { ISignature, ITransportCommand, TransportCryptoManager } from '@ts-core/common';
import { RSA } from '../RSA';
import * as _ from 'lodash';

export class TransportCryptoManagerRSA extends TransportCryptoManager {
    // --------------------------------------------------------------------------
    //
    //  Static Methods
    //
    // --------------------------------------------------------------------------

    public static ALGORITHM = 'RSA';

    // --------------------------------------------------------------------------
    //
    //  Public Methods
    //
    // --------------------------------------------------------------------------

    public async sign<U>(command: ITransportCommand<U>, nonce: string, privateKey: string): Promise<string> {
        return RSA.sign(this.toString(command, nonce), privateKey);
    }

    public async verify<U>(command: ITransportCommand<U>, signature: ISignature): Promise<boolean> {
        return RSA.verify(this.toString(command, signature.nonce), signature.value, signature.publicKey);
    }

    // --------------------------------------------------------------------------
    //
    //  Public Properties
    //
    // --------------------------------------------------------------------------

    public get algorithm(): string {
        return TransportCryptoManagerRSA.ALGORITHM;
    }
}
