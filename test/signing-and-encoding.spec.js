import assert from 'node:assert';
import {createSignedStateForPayload, getPayloadFromStateIfVerified} from '../index.js';
import {KeygripAutorotate} from 'keygrip-autorotate';

describe('github-email-authentication', () => {

    /**
     * @type {?KeygripAutorotate}
     */
    let grip;

    afterEach(() => {
        grip?.destroy();
        grip = null;
    });

    it('can create signed states for a payload, and retrieve the payload back from a verified state', () => {

        grip = new KeygripAutorotate({
            ttlPerSecret: 2 * 60 * 1000,
            totalSecrets: 2
        });

        const PAYLOAD = '__funny text #345lökös)%?§4098lßjrg98dgä-##____///--💩';

        let signature = createSignedStateForPayload(PAYLOAD, grip);
        let payloadFromSig = getPayloadFromStateIfVerified(signature, grip);

        assert.equal(payloadFromSig, PAYLOAD);
    });

    it(`can verify a signed state only for the duration of the signer's secrets TTL`, (done) => {

        grip = new KeygripAutorotate({
            ttlPerSecret: 1000,
            totalSecrets: 2
        });

        const PAYLOAD = '__funny text #345lökös)%?§4098lßjrg98dgä-##____///--💩';

        let signature = createSignedStateForPayload(PAYLOAD, grip);

        let checksRun = 0;

        for (let i = 0; i <= 3; i++) {
            setTimeout(() => {
                let payloadFromSig = getPayloadFromStateIfVerified(signature, grip);
                // console.log('payloadFromSig after %s ms -> %s', i * 250, payloadFromSig);
                assert.equal(payloadFromSig, PAYLOAD);
                checksRun++;
            }, i * 250)
        }

        setTimeout(() => {
            assert.equal(checksRun, 4);
            let payloadFromSig = getPayloadFromStateIfVerified(signature, grip);
            // secret TTL is over, so the signature should not be verifiable anymore
            // console.warn('payloadFromSig after secret TTL -> %s', payloadFromSig);
            assert(payloadFromSig === null);
            done();
        }, 1020)
    });

});
