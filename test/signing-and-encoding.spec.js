'use strict';

const assert = require('assert');
const {encodeSafeBase64, decodeUrlSafeBase64, createSignedStateForPayload, getPayloadFromStateIfVerified} = require('..');
const KeygripAutorotate = require('keygrip-autorotate');

const BASE64_REGEX = /^[0-9a-z_-]+$/i;

describe('github-email-authentication', () => {

    let grip;

    afterEach(() => {
        grip = void(!grip || grip.destroy());
    });

    it('can encode+decode url-safe base64 strings', () => {
        const TEXT = 'keine-spaß-blöd)"$/=)($§%?!"$?("_*_-und-12346-wei§9te!!!!r@nowhere-really-nowhere.nil-shit-💩';
        const urlsafe = encodeSafeBase64(TEXT);

        assert(BASE64_REGEX.test(urlsafe));
        assert.equal(decodeUrlSafeBase64(urlsafe), TEXT, 'decoded url-safe text should equal original one');
        // console.log('original:%s\nencoded: %s\ndecoded: %s', TEXT, urlsafe, decodeUrlSafeBase64(urlsafe));
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