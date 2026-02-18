// Import Express.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const bodyParser = require('body-parser');

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;

// Load private key for decryption (commented out for mock API)
// const privateKey = fs.readFileSync('/etc/secrets/private_key.pem', 'utf8');
// console.log('Private key loaded successfully');
const privateKey = 'mock-private-key'; // Mock key for testing

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
  // "hmac" field: full HMAC hash provided in metadata (actual payload format)
  const expectedHmac = encryption_metadata.hmac;

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
  const hmacCalc = crypto.createHmac('sha256', hmacKeyBuffer);
  hmacCalc.update(ivBuffer);
  hmacCalc.update(ciphertext);
  const computedHmac = hmacCalc.digest();

  if (expectedHmac) {
    // Validate against full HMAC provided in metadata
    const expectedHmacBuffer = Buffer.from(expectedHmac, 'base64');
    if (!crypto.timingSafeEqual(computedHmac, expectedHmacBuffer)) {
      throw new Error(`HMAC validation failed for ${file_name}`);
    }
  } else {
    // Fallback: validate first 10 bytes appended to cdn_file
    const computedHmac10 = computedHmac.subarray(0, 10);
    if (!crypto.timingSafeEqual(hmac10, computedHmac10)) {
      throw new Error(`HMAC validation failed for ${file_name}`);
    }
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

// Process all media items from photo_picker, document_picker, or images
async function processFlowMedia(data) {
  const mediaItems = data.photo_picker || data.document_picker || data.images || [];
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

          // Process media from photo_picker, document_picker, or images
          if (data?.photo_picker || data?.document_picker || data?.images) {
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

// ================ MATIAS API MOCK ENDPOINTS ================

// Store generated tokens and invoices
const tokens = {};
const invoices = {};

// Authentication endpoint
app.post('/api/ubl2.1/auth/login', (req, res) => {
  console.log('Authentication request received:', req.body);
  
  const { email, password } = req.body;
  
  // Simple validation
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    });
  }
  
  // Generate mock token
  const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjM' + 
                crypto.randomBytes(64).toString('hex');
  
  // Store token with expiration
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 30); // 30 days from now
  
  tokens[token] = {
    email,
    expiresAt: expiresAt.toISOString().replace('T', ' ').slice(0, 19)
  };
  
  console.log('Generated token:', token.substring(0, 20) + '...');
  
  // Return success response
  res.json({
    access_token: token,
    user: {
      id: 1,
      email: email,
      name: 'TU EMPRESA S.A.S.'
    },
    expires_at: expiresAt.toISOString().replace('T', ' ').slice(0, 19),
    message: 'Bienvenido a Matias. Su sesión ha sido iniciada con éxito.',
    success: true
  });
});

// Personal Access Token endpoint
app.post('/api/ubl2.1/v3/auth/tokens', (req, res) => {
  console.log('PAT request received');
  
  // Check authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: No token provided'
    });
  }
  
  const token = authHeader.split(' ')[1];
  if (!tokens[token]) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid token'
    });
  }
  
  const { name, expires_in_days } = req.body;
  
  if (!name) {
    return res.status(400).json({
      success: false,
      message: 'Name is required for Personal Access Token'
    });
  }
  
  // Generate new PAT
  const pat = 'pat_' + crypto.randomBytes(32).toString('hex');
  
  // Store PAT with expiration
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + (expires_in_days || 30));
  
  tokens[pat] = {
    name,
    expiresAt: expiresAt.toISOString().replace('T', ' ').slice(0, 19),
    type: 'personal'
  };
  
  console.log('Generated PAT:', pat.substring(0, 20) + '...');
  
  // Return success response
  res.json({
    token: pat,
    name,
    expires_at: expiresAt.toISOString().replace('T', ' ').slice(0, 19),
    success: true
  });
});

// Invoice creation endpoint
app.post('/api/invoices', (req, res) => {
  console.log('Invoice creation request received');
  
  // Check authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: No token provided'
    });
  }
  
  const token = authHeader.split(' ')[1];
  if (!tokens[token]) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid token'
    });
  }
  
  const invoiceData = req.body;
  console.log('Invoice data:', JSON.stringify(invoiceData, null, 2));
  
  // Basic validation
  if (!invoiceData.prefix || !invoiceData.document_number) {
    return res.status(400).json({
      success: false,
      message: 'Prefix and document_number are required'
    });
  }
  
  const invoiceId = `${invoiceData.prefix}-${invoiceData.document_number}`;
  
  // Check for duplicate
  if (invoices[invoiceId]) {
    return res.status(400).json({
      success: false,
      message: `El documento (Factura electrónica) con numero ${invoiceData.prefix}${invoiceData.document_number}, ya se encuentra validado`
    });
  }
  
  // Generate CUFE (Código Único de Facturación Electrónica)
  const cufe = 'd45f3b2ed042ce0e075891591c3b3a7ae3a9c176ca191dab1bd23e5cdd3b48b8c548a088dfcbe20ee7baa2bed2dccd48';
  
  // Store invoice
  invoices[invoiceId] = {
    ...invoiceData,
    cufe,
    created_at: new Date().toISOString(),
    status: 'processed'
  };
  
  console.log(`Invoice ${invoiceId} created successfully`);
  
  // Return success response
  res.json({
    message: 'El documento ha sido procesado por la DIAN.',
    send_to_queue: 0,
    XmlDocumentKey: cufe,
    response: {
      ErrorMessage: {
        string: []
      },
      IsValid: 'true',
      StatusCode: '00',
      StatusDescription: 'Procesado Correctamente.',
      StatusMessage: `La Factura electrónica ${invoiceData.prefix}${invoiceData.document_number}, ha sido autorizada.`,
      XmlBase64Bytes: '',
      XmlBytes: {
        _attributes: {
          nil: 'true'
        }
      },
      XmlDocumentKey: cufe,
      XmlFileName: `fv09010914030002500000095`
    },
    XmlBase64Bytes: '',
    AttachedDocument: {
      pathZip: '1/ad/z09010914030002500000042.zip',
      path: '1/ad/ad09010914030002500000041.xml',
      url: 'https://api-v2.matias-api.com/attachments/1/ad/ad09010914030002500000041.xml',
      data: ''
    },
    qr: {
      qrDian: '',
      url: '',
      path: '1/fv09010914030002500000095.png',
      data: ''
    },
    pdf: {
      path: '1/fv09010914030002500000095.pdf',
      url: `https://api-v2.matias-api.com/pdf/1/fv09010914030002500000095.pdf`,
      data: ''
    },
    success: true
  });
});

// Invoice query endpoint
app.get('/api/invoices/:invoiceId', (req, res) => {
  const invoiceId = req.params.invoiceId;
  console.log(`Query for invoice ${invoiceId}`);
  
  // Check authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: No token provided'
    });
  }
  
  const token = authHeader.split(' ')[1];
  if (!tokens[token]) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid token'
    });
  }
  
  // Check if invoice exists
  if (!invoices[invoiceId]) {
    return res.status(404).json({
      success: false,
      message: `Invoice ${invoiceId} not found`
    });
  }
  
  const invoice = invoices[invoiceId];
  const cufe = invoice.cufe;
  
  // Return invoice details
  res.json({
    message: 'El documento ha sido procesado por la DIAN.',
    send_to_queue: 0,
    XmlDocumentKey: cufe,
    response: {
      ErrorMessage: {
        string: []
      },
      IsValid: 'true',
      StatusCode: '00',
      StatusDescription: 'Procesado Correctamente.',
      StatusMessage: `La Factura electrónica ${invoice.prefix}${invoice.document_number}, ha sido autorizada.`,
      XmlBase64Bytes: '',
      XmlBytes: {
        _attributes: {
          nil: 'true'
        }
      },
      XmlDocumentKey: cufe,
      XmlFileName: `fv09010914030002500000095`
    },
    XmlBase64Bytes: '',
    AttachedDocument: {
      pathZip: '1/ad/z09010914030002500000042.zip',
      path: '1/ad/ad09010914030002500000041.xml',
      url: 'https://api-v2.matias-api.com/attachments/1/ad/ad09010914030002500000041.xml',
      data: ''
    },
    qr: {
      qrDian: '',
      url: '',
      path: '1/fv09010914030002500000095.png',
      data: ''
    },
    pdf: {
      path: '1/fv09010914030002500000095.pdf',
      url: `https://api-v2.matias-api.com/pdf/1/fv09010914030002500000095.pdf`,
      data: ''
    },
    success: true
  });
});

// Email sending endpoint
app.post('/api/invoices/:invoiceId/send-email', (req, res) => {
  const invoiceId = req.params.invoiceId;
  console.log(`Send email request for invoice ${invoiceId}`);
  
  // Check authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: No token provided'
    });
  }
  
  const token = authHeader.split(' ')[1];
  if (!tokens[token]) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Invalid token'
    });
  }
  
  // Check if invoice exists
  if (!invoices[invoiceId]) {
    return res.status(404).json({
      success: false,
      message: `Invoice ${invoiceId} not found`
    });
  }
  
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({
      success: false,
      message: 'Email is required'
    });
  }
  
  console.log(`Email would be sent to ${email} for invoice ${invoiceId}`);
  
  // Return success response
  res.json({
    success: true,
    message: `Email sent successfully to ${email}`
  });
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
  console.log('Matias API mock endpoints available:');
  console.log('- POST /api/ubl2.1/auth/login (Authentication)');
  console.log('- POST /api/ubl2.1/v3/auth/tokens (Personal Access Tokens)');
  console.log('- POST /api/invoices (Create invoice)');
  console.log('- GET /api/invoices/:invoiceId (Query invoice)');
  console.log('- POST /api/invoices/:invoiceId/send-email (Send email)');
});
