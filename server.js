const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Multer configuration
const upload = multer({ dest: 'uploads/' });

// Tạo thư mục keys nếu chưa tồn tại
const keysDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir);
}

// Tạo cặp khóa RSA 2048-bit nếu chưa tồn tại
const privateKeyPath = path.join(keysDir, 'private_key.pem');
const publicKeyPath = path.join(keysDir, 'public_key.pem');

if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
    console.log('Tạo cặp khóa RSA...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    fs.writeFileSync(privateKeyPath, privateKey);
    fs.writeFileSync(publicKeyPath, publicKey);
    console.log('Khóa RSA đã được tạo thành công!');
}

// Đọc khóa
const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
const publicKey = fs.readFileSync(publicKeyPath, 'utf8');

// Lưu trữ session tạm thời
let sessions = {};
let fileStorage = {};

// 1. Bắt tay - Hello
app.post('/api/handshake', (req, res) => {
    const { message } = req.body;
    console.log(`[${new Date().toISOString()}] Handshake nhận: ${message}`);
    
    if (message === 'Hello!') {
        const sessionId = crypto.randomBytes(16).toString('hex');
        sessions[sessionId] = {
            status: 'handshake_complete',
            timestamp: new Date()
        };
        
        console.log(`[${new Date().toISOString()}] Handshake hoàn thành, SessionID: ${sessionId}`);
        res.json({ 
            message: 'Ready!', 
            sessionId: sessionId,
            publicKey: publicKey 
        });
    } else {
        res.status(400).json({ error: 'Invalid handshake message' });
    }
});

// 2. Nhận file và xử lý mã hóa
app.post('/api/send-file', upload.single('file'), (req, res) => {
    try {
        const { sessionId, filename, expiration } = req.body;
        const file = req.file;
        
        console.log(`[${new Date().toISOString()}] Nhận file: ${filename}, Session: ${sessionId}`);
        
        if (!sessions[sessionId]) {
            return res.status(401).json({ error: 'Invalid session' });
        }
        
        // Đọc nội dung file
        const fileContent = fs.readFileSync(file.path);
        
        // Tạo session key cho AES
        const sessionKey = crypto.randomBytes(32); // 256-bit key
        const iv = crypto.randomBytes(16); // 128-bit IV
        
        // Mã hóa file bằng AES-CBC
        const cipher = crypto.createCipheriv('aes-256-cbc', sessionKey, iv);
        const ciphertext = Buffer.concat([cipher.update(fileContent), cipher.final()]);
        
        // Tạo metadata để ký, sử dụng thời gian hết hạn
        const metadata = `${filename}|${expiration}`;
        
        // Ký metadata bằng RSA/SHA-512
        const sign = crypto.createSign('RSA-SHA512');
        sign.update(metadata);
        const signature = sign.sign(privateKey, 'base64');
        
        // Mã hóa session key bằng RSA với OAEP padding
        const encryptedSessionKey = crypto.publicEncrypt({
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, sessionKey);
        
        // Tính hash toàn vẹn
        const hashData = Buffer.concat([iv, ciphertext, Buffer.from(expiration)]);
        const hash = crypto.createHash('sha512').update(hashData).digest('hex');
        
        // Tạo gói tin
        const packet = {
            iv: iv.toString('base64'),
            ciphertext: ciphertext.toString('base64'),
            hash: hash,
            signature: signature,
            exp: expiration,
            encryptedSessionKey: encryptedSessionKey.toString('base64'),
            filename: filename
        };
        
        // Lưu vào storage
        const fileId = crypto.randomBytes(16).toString('hex');
        fileStorage[fileId] = packet;
        
        console.log(`[${new Date().toISOString()}] File đã được mã hóa và lưu trữ, FileID: ${fileId}`);
        
        // Xóa file tạm
        fs.unlinkSync(file.path);
        
        res.json({ 
            success: true, 
            fileId: fileId,
            message: 'File đã được mã hóa và sẵn sàng gửi'
        });
        
    } catch (error) {
        console.error('Lỗi khi xử lý file:', error);
        res.status(500).json({ error: 'Lỗi server khi xử lý file' });
    }
});

// 3. Nhận file (phía người nhận)
app.post('/api/receive-file', (req, res) => {
    try {
        const { fileId } = req.body;
        
        console.log(`[${new Date().toISOString()}] Yêu cầu nhận file: ${fileId}`);
        
        if (!fileStorage[fileId]) {
            return res.status(404).json({ error: 'File không tồn tại' });
        }
        
        const packet = fileStorage[fileId];
        const currentTime = new Date();
        const expirationTime = new Date(packet.exp);
        
        console.log(`[${new Date().toISOString()}] Kiểm tra thời hạn: ${currentTime} <= ${expirationTime}`);
        
        // Kiểm tra thời hạn
        if (currentTime > expirationTime) {
            console.log(`[${new Date().toISOString()}] File đã hết hạn`);
            return res.status(410).json({ 
                error: 'TIMEOUT',
                message: 'File đã hết hạn' 
            });
        }
        
        // Kiểm tra hash toàn vẹn
        const iv = Buffer.from(packet.iv, 'base64');
        const ciphertext = Buffer.from(packet.ciphertext, 'base64');
        const hashData = Buffer.concat([iv, ciphertext, Buffer.from(packet.exp)]);
        const calculatedHash = crypto.createHash('sha512').update(hashData).digest('hex');
        
        if (calculatedHash !== packet.hash) {
            console.log(`[${new Date().toISOString()}] Hash không khớp`);
            return res.status(400).json({ 
                error: 'INTEGRITY',
                message: 'Tính toàn vẹn file bị vi phạm' 
            });
        }
        
        // Kiểm tra chữ ký, sử dụng thời gian hết hạn
        const metadata = `${packet.filename}|${packet.exp}`;
        const verify = crypto.createVerify('RSA-SHA512');
        verify.update(metadata);
        const isValidSignature = verify.verify(publicKey, packet.signature, 'base64');
        
        if (!isValidSignature) {
            console.log(`[${new Date().toISOString()}] Chữ ký không hợp lệ`);
            return res.status(400).json({ 
                error: 'SIGNATURE',
                message: 'Chữ ký không hợp lệ' 
            });
        }
        
        // Giải mã session key bằng RSA với OAEP padding
        const encryptedSessionKey = Buffer.from(packet.encryptedSessionKey, 'base64');
        const sessionKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
        }, encryptedSessionKey);
        
        // Giải mã file
        const decipher = crypto.createDecipheriv('aes-256-cbc', sessionKey, iv);
        const decryptedContent = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        
        // Lưu file
        const outputPath = path.join(__dirname, 'received', packet.filename);
        if (!fs.existsSync(path.dirname(outputPath))) {
            fs.mkdirSync(path.dirname(outputPath), { recursive: true });
        }
        fs.writeFileSync(outputPath, decryptedContent);
        
        console.log(`[${new Date().toISOString()}] File đã được giải mã và lưu: ${outputPath}`);
        
        // Xóa file khỏi storage sau khi nhận thành công
        delete fileStorage[fileId];
        
        res.json({ 
            success: true,
            message: 'ACK - File đã được nhận và giải mã thành công',
            filename: packet.filename,
            savedPath: outputPath
        });
        
    } catch (error) {
        console.error('Lỗi khi nhận file:', error);
        res.status(500).json({ 
            error: 'NACK',
            message: 'Lỗi server khi xử lý file' 
        });
    }
});

// API để lấy danh sách file có sẵn
app.get('/api/available-files', (req, res) => {
    const files = Object.keys(fileStorage).map(fileId => ({
        fileId: fileId,
        filename: fileStorage[fileId].filename,
        expiration: fileStorage[fileId].exp,
        timeLeft: Math.max(0, Math.floor((new Date(fileStorage[fileId].exp) - new Date()) / 1000))
    }));
    
    res.json(files);
});

// Khởi động server
app.listen(PORT, () => {
    console.log(`Server đang chạy tại http://localhost:${PORT}`);
    console.log('Khóa RSA đã sẵn sàng trong thư mục keys/');
});