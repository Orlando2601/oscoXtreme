// Import Express.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;

// Load private key for decryption
const privateKey = fs.readFileSync('/etc/secrets/private_key.pem', 'utf8');
console.log('Private key loaded successfully');

const TAG_LENGTH = 16;

// Decrypt request (based on official Meta implementation)
function decryptRequest(body) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  // Decrypt AES key with RSA private key
  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encrypted_aes_key, 'base64')
  );

  // Decrypt flow data with AES-128-GCM
  const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
  const initialVectorBuffer = Buffer.from(initial_vector, 'base64');

  const encrypted_flow_data_body = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const encrypted_flow_data_tag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv(
    'aes-128-gcm',
    decryptedAesKey,
    initialVectorBuffer
  );
  decipher.setAuthTag(encrypted_flow_data_tag);

  const decryptedJSONString = Buffer.concat([
    decipher.update(encrypted_flow_data_body),
    decipher.final(),
  ]).toString('utf-8');

  return {
    decryptedBody: JSON.parse(decryptedJSONString),
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer,
  };
}

// Encrypt response (based on official Meta implementation)
function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
  // Flip initial vector
  const flipped_iv = [];
  for (const pair of initialVectorBuffer.entries()) {
    flipped_iv.push(~pair[1]);
  }

  // Encrypt response data
  const cipher = crypto.createCipheriv(
    'aes-128-gcm',
    aesKeyBuffer,
    Buffer.from(flipped_iv)
  );
  return Buffer.concat([
    cipher.update(JSON.stringify(response), 'utf-8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString('base64');
}

// Route for GET requests
app.get('/', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    res.status(403).end();
  }
});

// Route for POST requests
app.post('/', (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n\nWebhook received ${timestamp}\n`);
  console.log(JSON.stringify(req.body, null, 2));

  // Handle WhatsApp Flow requests with encrypted data
  if (req.body.encrypted_flow_data && req.body.encrypted_aes_key && req.body.initial_vector) {
    try {
      // Decrypt the request
      const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(req.body);
      console.log('Decrypted flow data:', decryptedBody);

      // Handle different flow actions
      let responseData;

      if (decryptedBody.action === 'ping') {
        responseData = {
          version: decryptedBody.version,
          data: {
            status: 'active'
          }
        };
        console.log('Responding to ping action');
      } else if (decryptedBody.action === 'data_exchange') {
        const screen = decryptedBody.screen;
        const data = decryptedBody.data;
        
        console.log('Data exchange received from screen:', screen);
        console.log('Data payload:', JSON.stringify(data, null, 2));
        
        // Handle navigation from WELCOME screen
        if (screen === 'WELCOME') {
          const accion = data?.accion;
          console.log('Navigation request for action:', accion);
          
          if (accion === 'cargar_factura') {
            responseData = {
              version: decryptedBody.version,
              screen: 'CARGAR_FACTURA',
              data: {}
            };
            console.log('Navigating to CARGAR_FACTURA screen');
          } else if (accion === 'crear_cliente') {
            responseData = {
              version: decryptedBody.version,
              screen: 'CREAR_CLIENTE',
              data: {}
            };
            console.log('Navigating to CREAR_CLIENTE screen');
          } else {
            // Default to SUCCESS for unknown actions
            responseData = {
              version: decryptedBody.version,
              screen: 'SUCCESS',
              data: {
                extension_message_response: {
                  params: {
                    flow_token: decryptedBody.flow_token || 'FLOW_TOKEN'
                  }
                }
              }
            };
          }
        } else {
          // Terminal screens - close the flow and show the data
          console.log('Terminal screen completion');
          
          // Extract image data if present
          if (data?.images && Array.isArray(data.images)) {
            console.log('Images received:', data.images.length);
            data.images.forEach((image, index) => {
              console.log(`Image ${index}:`, JSON.stringify(image, null, 2));
            });
          }
          
          responseData = {
            version: decryptedBody.version,
            screen: 'SUCCESS',
            data: {
              extension_message_response: {
                params: {
                  flow_token: decryptedBody.flow_token || 'FLOW_TOKEN'
                }
              }
            }
          };
          console.log('Flow completed successfully');
        }
      } else {
        responseData = {
          version: decryptedBody.version,
          data: {}
        };
      }

      // Encrypt and send response
      const encryptedResponseBase64 = encryptResponse(responseData, aesKeyBuffer, initialVectorBuffer);
      console.log('Sending encrypted response');
      res.status(200).send(encryptedResponseBase64);
      return;

    } catch (error) {
      console.error('Error processing flow data:', error);
      // Return 421 if decryption fails (to refresh public key)
      if (error.message && error.message.includes('decrypt')) {
        res.status(421).end();
      } else {
        res.status(500).end();
      }
      return;
    }
  }

  // Default response for regular webhook events
  res.status(200).end();
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
