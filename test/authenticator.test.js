const { expect } = require('chai');
const { authenticate } = require('../index.js');

describe('Authenticator Module', function() {
    it('should throw error if loginUrl is not provided', async function() {
        try {
            await authenticate();
            throw new Error('Expected error was not thrown');
        } catch (error) {
            expect(error.message).to.equal('loginUrl is required');
        }
    });

    it('should return a Promise when loginUrl is provided', function() {
        const result = authenticate('http://dummy-login-url.com');
        expect(result).to.be.an.instanceof(Promise);
    });
});
