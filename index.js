const express = require('express');
const multer = require('multer');
const { DefaultAzureCredential } = require('@azure/identity');
const { BlobServiceClient } = require('@azure/storage-blob');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;
const mime = require('mime-types');


const app = express();
const upload = multer({ dest: 'uploads/' });

app.use(cors());
app.use(express.static('public'));
app.use(session({ secret: 'yourSecret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Azure Blob Storage
const accountName = "azprojectblob";
const containerName = "azcontainer";
const credential = new DefaultAzureCredential();
const blobServiceClient = new BlobServiceClient(
  `https://${accountName}.blob.core.windows.net`,
  credential
);
const containerClient = blobServiceClient.getContainerClient(containerName);

// Azure AD Passport Config
passport.use(new OIDCStrategy({
  identityMetadata: `https://login.microsoftonline.com/75df096c-8b72-48e4-9b91-cbf79d87ee3a/v2.0/.well-known/openid-configuration`,
  clientID: 'cb924d9e-8528-4744-b152-4339712ae756',
  clientSecret: 'ciC8Q~Ydt4uxizSaSMditiBh36ctwNDVN5IV8cQN',
  responseType: 'code',
  responseMode: 'query',
  redirectUrl: 'http://localhost:3000/auth/redirect',
  allowHttpForRedirectUrl: true,
  scope: ['profile', 'email', 'openid']
}, function(iss, sub, profile, accessToken, refreshToken, done) {
  if (!profile.oid) return done(new Error("No OID found"), null);
  return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}

// Auth Routes
app.get('/login', passport.authenticate('azuread-openidconnect'));
app.get('/auth/redirect',
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/' }),
  (req, res) => res.redirect('/')
);
app.get('/logout', (req, res) => {
  req.logout(err => res.redirect('/'));
});
app.get('/me', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).send('Not logged in');
  res.send(req.user);
});

// Multiple File Upload
app.post('/upload', ensureAuthenticated, upload.array('files'), async (req, res) => {
  try {
    const uploadResults = [];

    for (const file of req.files) {
      const blobName = file.originalname;
      const blockBlobClient = containerClient.getBlockBlobClient(blobName);
      await blockBlobClient.uploadFile(file.path);
      fs.unlinkSync(file.path);
      uploadResults.push(blobName);
    }

    res.send({ message: `Uploaded ${uploadResults.length} files.`, files: uploadResults });
  } catch (err) {
    console.error('Upload error:', err.message);
    res.status(500).send({ error: err.message });
  }
});

// List Files
app.get('/files', ensureAuthenticated, async (req, res) => {
  try {
    const files = [];
    for await (const blob of containerClient.listBlobsFlat()) {
      files.push(blob.name);
    }
    res.send(files);
  } catch (err) {
    console.error('List error:', err.message);
    res.status(500).send({ error: err.message });
  }
});

// Download File
app.get('/download/:filename', ensureAuthenticated, async (req, res) => {
  try {
    const blobClient = containerClient.getBlobClient(req.params.filename);
    const downloadBlockBlobResponse = await blobClient.download();
    res.setHeader('Content-Disposition', `attachment; filename=${req.params.filename}`);
    downloadBlockBlobResponse.readableStreamBody.pipe(res);
  } catch (err) {
    console.error('Download error:', err.message);
    res.status(500).send({ error: err.message });
  }
});

// Delete File
app.delete('/delete/:filename', ensureAuthenticated, async (req, res) => {
  try {
    const blobClient = containerClient.getBlobClient(req.params.filename);
    await blobClient.deleteIfExists();
    res.send({ message: 'Deleted' });
  } catch (err) {
    console.error('Delete error:', err.message);
    res.status(500).send({ error: err.message });
  }
});

// Update File (Re-upload)
app.post('/update', ensureAuthenticated, upload.single('file'), async (req, res) => {
  try {
    const blobName = req.file.originalname;
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);
    await blockBlobClient.uploadFile(req.file.path, { overwrite: true });
    fs.unlinkSync(req.file.path);
    res.send({ message: 'Updated' });
  } catch (err) {
    console.error('Update error:', err.message);
    res.status(500).send({ error: err.message });
  }
});

app.get('/preview/:filename', ensureAuthenticated, async (req, res) => {
  try {
    const blobClient = containerClient.getBlobClient(req.params.filename);
    const downloadResponse = await blobClient.download();
    const contentType = blobClient.name.match(/\.(jpg|jpeg|png|gif)$/i)
      ? 'image/' + blobClient.name.split('.').pop()
      : blobClient.name.match(/\.(txt|md|log|csv|json|js|html|css)$/i)
      ? 'text/plain'
      : 'application/octet-stream';

    res.setHeader('Content-Type', contentType);
    downloadResponse.readableStreamBody.pipe(res);
  } catch (err) {
    console.error('Preview error:', err.message);
    res.status(500).send({ error: err.message });
  }
});
app.get('/analytics', ensureAuthenticated, async (req, res) => {
  try {
    const fileCategories = {
      Images: 0,
      Text: 0,
      Others: 0,
    };
    let totalSize = 0;
    let fileCount = 0;

    for await (const blob of containerClient.listBlobsFlat()) {
      fileCount++;
      totalSize += blob.properties.contentLength || 0;

      const ext = path.extname(blob.name).toLowerCase();

      if (ext.match(/\.(jpg|jpeg|png|gif)$/i)) {
        fileCategories.Images++;
      } else if (ext.match(/\.(txt|md|log|csv|json|js|html|css)$/i)) {
        fileCategories.Text++;
      } else {
        fileCategories.Others++;
      }
    }

    res.json({
      totalFiles: fileCount,
      totalSizeMB: (totalSize / (1024 * 1024)).toFixed(2),
      fileCategories
    });
  } catch (err) {
    console.error('Analytics error:', err.message);
    res.status(500).json({ error: err.message });
  }
});


app.listen(3000, () => console.log('Server started at http://localhost:3000'));
