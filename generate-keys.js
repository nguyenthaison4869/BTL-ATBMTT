const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Tạo thư mục keys nếu chưa tồn tại
const keysDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir);
    console.log('Đã tạo thư mục keys/');
}

console.log('Đang tạo cặp khóa RSA 2048-bit...');

// Tạo cặp khóa RSA 2048-bit
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

// Đường dẫn file khóa
const privateKeyPath = path.join(keysDir, 'private_key.pem');
const publicKeyPath = path.join(keysDir, 'public_key.pem');

// Lưu khóa riêng tư
fs.writeFileSync(privateKeyPath, privateKey);
console.log(`✓ Khóa riêng tư đã lưu: ${privateKeyPath}`);

// Lưu khóa công khai
fs.writeFileSync(publicKeyPath, publicKey);
console.log(`✓ Khóa công khai đã lưu: ${publicKeyPath}`);

// Hiển thị thông tin khóa
console.log('\n=== THÔNG TIN KHÓA ===');
console.log('Thuật toán: RSA 2048-bit');
console.log('Padding: PKCS#1 v1.5');
console.log('Hash: SHA-512');
console.log('Mã hóa: PKCS#8 (Private), SPKI (Public)');

// Kiểm tra khóa
console.log('\n=== KIỂM TRA KHÓA ===');
try {
    // Test mã hóa và giải mã
    const testData = 'Hello, this is a test message!';
    
    // Mã hóa với khóa công khai
    const encrypted = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, Buffer.from(testData));
    
    // Giải mã với khóa riêng tư
    const decrypted = crypto.privateDecrypt({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, encrypted);
    
    if (decrypted.toString() === testData) {
        console.log('✓ Khóa hoạt động bình thường');
    } else {
        console.log('✗ Lỗi kiểm tra khóa');
    }
    
    // Test chữ ký
    const sign = crypto.createSign('RSA-SHA512');
    sign.update(testData);
    const signature = sign.sign(privateKey);
    
    const verify = crypto.createVerify('RSA-SHA512');
    verify.update(testData);
    const isValid = verify.verify(publicKey, signature);
    
    if (isValid) {
        console.log('✓ Chữ ký hoạt động bình thường');
    } else {
        console.log('✗ Lỗi kiểm tra chữ ký');
    }
    
} catch (error) {
    console.log('✗ Lỗi kiểm tra khóa:', error.message);
}

console.log('\n=== HOÀN THÀNH ===');
console.log('Khóa RSA đã được tạo thành công!');
console.log('Bây giờ bạn có thể chạy server với: npm start');