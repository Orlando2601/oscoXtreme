// Import Express.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

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

// Media storage directory
const MEDIA_DIR = path.join(__dirname, 'media_downloads');
if (!fs.existsSync(MEDIA_DIR)) {
  fs.mkdirSync(MEDIA_DIR, { recursive: true });
}

// Download media file from WhatsApp CDN
async function downloadMediaFromCDN(cdnUrl) {
  const response = await axios.get(cdnUrl, { responseType: 'arraybuffer' });
  return Buffer.from(response.data);
}

// Decrypt and validate WhatsApp Flow media
// cdn_file = ciphertext + hmac10 (last 10 bytes are first 10 bytes of HMAC-SHA256)
// Uses AES256-CBC + HMAC-SHA256 + PKCS7 padding
async function decryptAndValidateMedia(mediaItem) {
  const { media_id, cdn_url, file_name, encryption_metadata } = mediaItem;
  const { encrypted_hash, iv, encryption_key, hmac_key, plaintext_hash } = encryption_metadata;

  console.log(`Processing media: ${file_name} (${media_id})`);

  // Step 1: Download cdn_file from cdn_url
  const cdnFile = await downloadMediaFromCDN(cdn_url);
  console.log(`Downloaded ${cdnFile.length} bytes from CDN`);

  // Step 2: Validate SHA256(cdn_file) == encrypted_hash
  const cdnFileHash = crypto.createHash('sha256').update(cdnFile).digest('base64');
  if (cdnFileHash !== encrypted_hash) {
    throw new Error(`Encrypted hash mismatch for ${file_name}: expected ${encrypted_hash}, got ${cdnFileHash}`);
  }
  console.log(`Encrypted hash validated for ${file_name}`);

  // Step 3: Split cdn_file into ciphertext and hmac10
  const ciphertext = cdnFile.subarray(0, -10);
  const hmac10 = cdnFile.subarray(-10);

  // Step 4: Validate HMAC-SHA256
  const ivBuffer = Buffer.from(iv, 'base64');
  const hmacKeyBuffer = Buffer.from(hmac_key, 'base64');
  const hmac = crypto.createHmac('sha256', hmacKeyBuffer);
  hmac.update(ivBuffer);
  hmac.update(ciphertext);
  const computedHmac = hmac.digest();
  const computedHmac10 = computedHmac.subarray(0, 10);

  if (!crypto.timingSafeEqual(hmac10, computedHmac10)) {
    throw new Error(`HMAC validation failed for ${file_name}`);
  }
  console.log(`HMAC validated for ${file_name}`);

  // Step 5: Decrypt media with AES-256-CBC
  const encKeyBuffer = Buffer.from(encryption_key, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-cbc', encKeyBuffer, ivBuffer);
  decipher.setAutoPadding(true); // PKCS7 padding removal
  const decryptedMedia = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  console.log(`Decrypted ${decryptedMedia.length} bytes for ${file_name}`);

  // Step 6: Validate SHA256(decrypted_media) == plaintext_hash
  const decryptedHash = crypto.createHash('sha256').update(decryptedMedia).digest('base64');
  if (decryptedHash !== plaintext_hash) {
    throw new Error(`Plaintext hash mismatch for ${file_name}: expected ${plaintext_hash}, got ${decryptedHash}`);
  }
  console.log(`Plaintext hash validated for ${file_name}`);

  // Save decrypted media to disk
  const outputPath = path.join(MEDIA_DIR, `${media_id}_${file_name}`);
  fs.writeFileSync(outputPath, decryptedMedia);
  console.log(`Media saved to ${outputPath}`);

  return { media_id, file_name, outputPath, size: decryptedMedia.length };
}

// Process all media items from photo_picker or document_picker
async function processFlowMedia(data) {
  const mediaItems = data.photo_picker || data.document_picker || [];
  if (mediaItems.length === 0) return [];

  console.log(`Processing ${mediaItems.length} media item(s)`);
  const results = [];
  for (const item of mediaItems) {
    try {
      const result = await decryptAndValidateMedia(item);
      results.push(result);
    } catch (err) {
      console.error(`Failed to process media ${item.file_name}:`, err.message);
      results.push({ media_id: item.media_id, file_name: item.file_name, error: err.message });
    }
  }
  return results;
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
app.post('/', async (req, res) => {
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

          // Process media from photo_picker or document_picker
          if (data?.photo_picker || data?.document_picker) {
            const mediaResults = await processFlowMedia(data);
            console.log('Media processing results:', JSON.stringify(mediaResults, null, 2));
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

  // Handle Cloud API nfm_reply with media (photo_picker / document_picker)
  try {
    const messages = req.body?.entry?.[0]?.changes?.[0]?.value?.messages;
    if (messages) {
      for (const message of messages) {
        const nfmReply = message?.interactive?.nfm_reply;
        if (nfmReply?.response_json) {
          const responseJson = typeof nfmReply.response_json === 'string'
            ? JSON.parse(nfmReply.response_json)
            : nfmReply.response_json;

          const mediaItems = responseJson.photo_picker || responseJson.document_picker || [];
          if (mediaItems.length > 0) {
            console.log(`Cloud API nfm_reply contains ${mediaItems.length} media item(s)`);
            for (const item of mediaItems) {
              console.log(`Media: ${item.file_name} (id: ${item.id}, mime: ${item.mime_type}, sha256: ${item.sha256})`);
            }
          }
        }
      }
    }
  } catch (err) {
    console.error('Error processing nfm_reply media:', err.message);
  }

  // Default response for regular webhook events
  res.status(200).end();
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
