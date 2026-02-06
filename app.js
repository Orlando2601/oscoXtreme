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

// Load public key for encryption
const publicKey = fs.readFileSync('/etc/secrets/public_key.pem', 'utf8');
console.log('Public key loaded successfully');

// Function to decrypt base64 payload
function decryptPayload(base64Payload) {
  try {
    const encryptedBuffer = Buffer.from(base64Payload, 'base64');
    const decrypted = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      encryptedBuffer
    );
    return JSON.parse(decrypted.toString());
  } catch (error) {
    console.error('Error decrypting payload:', error);
    return null;
  }
}

// Function to encrypt response payload
function encryptResponse(responseData) {
  try {
    const responseString = JSON.stringify(responseData);
    const encrypted = crypto.publicEncrypt(
      {
        key: fs.readFileSync('/etc/secrets/public_key.pem', 'utf8'),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      Buffer.from(responseString)
    );
    return encrypted.toString('base64');
  } catch (error) {
    console.error('Error encrypting response:', error);
    return null;
  }
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
      console.log('Processing WhatsApp Flow request...');
      
      // Decrypt AES key with private key
      const encryptedAesKey = Buffer.from(req.body.encrypted_aes_key, 'base64');
      console.log('Encrypted AES key length:', encryptedAesKey.length);
      
      let aesKey;
      try {
        // Try OAEP padding first
        aesKey = crypto.privateDecrypt(
          {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
          },
          encryptedAesKey
        );
      } catch (oaepError) {
        console.log('OAEP failed, trying PKCS1 padding...');
        try {
          // Try PKCS1 padding
          aesKey = crypto.privateDecrypt(
            {
              key: privateKey,
              padding: crypto.constants.RSA_PKCS1_PADDING
            },
            encryptedAesKey
          );
        } catch (pkcs1Error) {
          console.log('PKCS1 failed, trying no padding...');
          // Try no padding
          aesKey = crypto.privateDecrypt(
            {
              key: privateKey,
              padding: crypto.constants.RSA_NO_PADDING
            },
            encryptedAesKey
          );
        }
      }
      
      console.log('Decrypted AES key length:', aesKey.length);
      console.log('Decrypted AES key (hex):', aesKey.toString('hex'));

      // Determine AES algorithm based on key length
      let aesAlgorithm;
      if (aesKey.length === 32) {
        aesAlgorithm = 'aes-256-cbc';
      } else if (aesKey.length === 24) {
        aesAlgorithm = 'aes-192-cbc';
      } else if (aesKey.length === 16) {
        aesAlgorithm = 'aes-128-cbc';
      } else {
        // Pad or truncate to 32 bytes for AES-256
        if (aesKey.length > 32) {
          aesKey = aesKey.slice(0, 32);
        } else {
          const paddedKey = Buffer.alloc(32);
          aesKey.copy(paddedKey);
          aesKey = paddedKey;
        }
        aesAlgorithm = 'aes-256-cbc';
      }
      
      console.log('Using AES algorithm:', aesAlgorithm);
      console.log('Final AES key length:', aesKey.length);

      // Decrypt flow data with AES key
      const encryptedFlowData = Buffer.from(req.body.encrypted_flow_data, 'base64');
      const initialVector = Buffer.from(req.body.initial_vector, 'base64');
      
      console.log('Encrypted flow data length:', encryptedFlowData.length);
      console.log('Initial vector length:', initialVector.length);
      console.log('Encrypted flow data (hex):', encryptedFlowData.toString('hex'));
      
      // Check if data length suggests GCM mode (has auth tag)
      const hasAuthTag = encryptedFlowData.length % 16 !== 0 && encryptedFlowData.length > 16;
      
      // Use the correct algorithm and key length
      let decryptedData;
      let usedGcm = false;
      
      // Try AES-GCM first (WhatsApp might be using GCM instead of CBC)
      if (hasAuthTag) {
        console.log('Trying AES-GCM mode (data length suggests auth tag present)...');
        try {
          // Last 16 bytes are the auth tag in GCM
          const authTagLength = 16;
          const ciphertext = encryptedFlowData.slice(0, -authTagLength);
          const authTag = encryptedFlowData.slice(-authTagLength);
          
          console.log('Ciphertext length:', ciphertext.length);
          console.log('Auth tag length:', authTag.length);
          
          const gcmAlgorithm = aesAlgorithm.replace('-cbc', '-gcm');
          const decipher = crypto.createDecipheriv(gcmAlgorithm, aesKey, initialVector);
          decipher.setAuthTag(authTag);
          
          let partialData = decipher.update(ciphertext);
          decryptedData = Buffer.concat([partialData, decipher.final()]);
          usedGcm = true;
          aesAlgorithm = gcmAlgorithm; // Update for response encryption
          console.log('Decryption successful with AES-GCM');
        } catch (gcmError) {
          console.log('AES-GCM failed:', gcmError.message);
          console.log('Falling back to CBC mode...');
        }
      }
      
      // If GCM didn't work or wasn't attempted, try CBC
      if (!decryptedData) {
        try {
          const decipher = crypto.createDecipheriv(aesAlgorithm, aesKey, initialVector);
          let partialData = decipher.update(encryptedFlowData);
          decryptedData = Buffer.concat([partialData, decipher.final()]);
          console.log('Decryption successful with standard CBC padding');
        } catch (blockError) {
          console.log('Standard CBC decipher failed:', blockError.message);
          console.log('Trying with auto padding disabled...');
          try {
            const decipher = crypto.createDecipheriv(aesAlgorithm, aesKey, initialVector);
            decipher.setAutoPadding(false);
            let partialData = decipher.update(encryptedFlowData);
            decryptedData = Buffer.concat([partialData, decipher.final()]);
            
            console.log('Decrypted data (raw):', decryptedData.toString('hex'));
            
            // Remove PKCS7 padding manually
            const paddingLength = decryptedData[decryptedData.length - 1];
            console.log('Padding length:', paddingLength);
            if (paddingLength > 0 && paddingLength <= 16) {
              decryptedData = decryptedData.slice(0, -paddingLength);
            }
            console.log('Decryption successful with manual padding removal');
          } catch (noPadError) {
            console.log('Auto padding disabled also failed:', noPadError.message);
            
            // Last resort: try to decrypt without final()
            try {
              const decipher = crypto.createDecipheriv(aesAlgorithm, aesKey, initialVector);
              decipher.setAutoPadding(false);
              decryptedData = decipher.update(encryptedFlowData);
              console.log('Decryption successful with update only (no final)');
            } catch (updateOnlyError) {
              console.log('All decryption methods failed');
              throw blockError; // Re-throw the original error
            }
          }
        }
      }
      
      const flowData = JSON.parse(decryptedData.toString());
      console.log('Decrypted flow data:', flowData);

      // Prepare response
      const responseData = {
        status: 'success',
        message: 'Form received successfully',
        data: flowData
      };

      // Encrypt response with AES (using same key and new IV)
      const responseString = JSON.stringify(responseData);
      const responseIv = crypto.randomBytes(12); // GCM typically uses 12-byte IV
      
      let encryptedResponse;
      if (usedGcm) {
        console.log('Encrypting response with AES-GCM');
        const cipher = crypto.createCipheriv(aesAlgorithm, aesKey, responseIv);
        let encrypted = cipher.update(responseString);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const authTag = cipher.getAuthTag();
        // Combine encrypted data and auth tag
        encryptedResponse = Buffer.concat([encrypted, authTag]);
      } else {
        console.log('Encrypting response with AES-CBC');
        const cipher = crypto.createCipheriv(aesAlgorithm, aesKey, responseIv);
        let encrypted = cipher.update(responseString);
        encryptedResponse = Buffer.concat([encrypted, cipher.final()]);
      }
      
      // Encrypt AES key with public key
      const encryptedResponseKey = crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256'
        },
        aesKey
      );

      // Send response in expected format
      const finalResponse = {
        encrypted_flow_data: encryptedResponse.toString('base64'),
        encrypted_aes_key: encryptedResponseKey.toString('base64'),
        initial_vector: responseIv.toString('base64')
      };

      console.log('Sending encrypted response');
      res.status(200).json(finalResponse);
      return;

    } catch (error) {
      console.error('Error processing flow data:', error);
      console.error('Error stack:', error.stack);
      res.status(500).json({ error: 'Internal server error', details: error.message });
      return;
    }
  }

  // Handle WhatsApp Flow requests (old format - keep for compatibility)
  if (req.body.object === 'whatsapp_business_account' && req.body.entry) {
    for (const entry of req.body.entry) {
      if (entry.changes) {
        for (const change of entry.changes) {
          if (change.field === 'flows' && change.value && change.value.payload) {
            // Decrypt the incoming payload
            const decryptedData = decryptPayload(change.value.payload);
            console.log('Decrypted data:', decryptedData);

            // Process the form data (example: save to database, validate, etc.)
            
            // Prepare response
            const responseData = {
              status: 'success',
              message: 'Form received successfully',
              data: decryptedData
            };

            // Encrypt the response
            const encryptedResponse = encryptResponse(responseData);
            
            if (encryptedResponse) {
              // Send encrypted base64 response
              res.status(200).send(encryptedResponse);
            } else {
              res.status(500).end();
            }
            return;
          }
        }
      }
    }
  }

  // Default response for regular webhook events
  res.status(200).end();
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
