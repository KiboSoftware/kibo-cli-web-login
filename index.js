const crypto = require('crypto');
const http = require('http');

class Authenticator {
    constructor() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'der'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    decryptLargePayload(privateKeyPem, encryptedPayload) {
        const payload = JSON.parse(encryptedPayload);
        const encryptedKey = Buffer.from(payload.EncryptedKey, 'base64');
        const encryptedData = Buffer.from(payload.EncryptedData, 'base64');

        const privateKey = crypto.createPrivateKey(privateKeyPem);
        const combinedKey = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            encryptedKey
        );

        const aesKey = combinedKey.subarray(0, 32);
        const aesIv = combinedKey.subarray(32);

        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, aesIv);
        let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
        decryptedData += decipher.final('utf8');

        return JSON.parse(decryptedData);
    }

    async authenticate(loginUrl) {
        if (!loginUrl) {
            throw new Error('loginUrl is required');
        }
        return new Promise(async (resolve, reject) => {
            let open;
            try {
                const openModule = await import('open');
                open = openModule.default;
            } catch (e) {
                console.log("open package not found, please install it using npm install open");
                reject(e);
                return;
            }

            const port = Math.floor(Math.random() * (65535 - 1024) + 1024);
            const server = http.createServer((req, res) => {
                res.setHeader('Access-Control-Allow-Origin', '*');
                res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
                res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
                res.setHeader('Access-Control-Allow-Credentials', 'true');

                if (req.method === 'OPTIONS') {
                    res.writeHead(200);
                    res.end();
                    return;
                }

                if (req.method === 'POST') {
                    let body = '';
                    req.on('data', chunk => body += chunk.toString());
                    req.on('end', () => {
                        try {
                            const payload = new URLSearchParams(body).get('payload');
                            if (!payload) throw new Error('No payload provided');

                            const decryptedData = this.decryptLargePayload(this.privateKey, payload);
                            res.writeHead(200, { 'Content-Type': 'text/html' });
                            res.end(`
                                <!DOCTYPE html>
                                <html>
                                <head>
                                    <title>Authenticated to kibo</title>
                                    <style>
                                        body { background-color: black; color: white; text-align: center; font-family: sans-serif; }
                                        img { max-width: 200px; margin-top: 50px; }
                                        h1 { margin-top: 30px; }
                                    </style>
                                </head>
                                <body>
                                    <img src="https://kibocommerce.com/wp-content/uploads/2022/12/logo-kibo-ForDarkBG.svg" alt="kibo logo">
                                    <h1>Authentication Successful</h1>
                                    <p>You have successfully authenticated to kibo. You can now close this page.</p>
                                </body>
                                </html>
                            `);

                            server.close();
                            resolve(decryptedData);
                        } catch (error) {
                            console.error('Error:', error);
                            res.writeHead(400, { 'Content-Type': 'text/html' });
                            res.end(`
                                <!DOCTYPE html>
                                <html>
                                <head>
                                    <title>Error Authenticating to kibo</title>
                                    <style>
                                        body { background-color: black; color: white; text-align: center; font-family: sans-serif; }
                                        img { max-width: 200px; margin-top: 50px; }
                                        h1 { margin-top: 30px; }
                                    </style>
                                </head>
                                <body>
                                    <img src="https://kibocommerce.com/wp-content/uploads/2022/12/logo-kibo-ForDarkBG.svg" alt="kibo logo">
                                    <h1>Authentication Error</h1>
                                    <p>There was an error processing your authentication. Please try again.</p>
                                </body>
                                </html>
                            `);
                            reject(error);
                        }
                    });
                } else {
                    res.writeHead(404);
                    res.end();
                }
            });

            server.listen(port, () => {
                const nonce = '123';
                const cliState = {
                    publicKey: this.publicKey.toString('base64'),
                    nonce,
                    port
                };

                const encodedCliState = encodeURIComponent(
                    Buffer.from(JSON.stringify(cliState)).toString('base64')
                );

                const url = `${loginUrl}?PostbackUrl=http://localhost:${port}?cliState=${encodedCliState}&scopeType=developer`;
                console.log('Opening browser...');
                open(url).catch(reject);
            });

            setTimeout(() => {
                server.close();
                reject(new Error('Authentication timed out'));
            }, 300000);
        });
    }
}

module.exports = {
    authenticate: (login) => new Authenticator().authenticate(login)
};
