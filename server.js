const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// إنشاء الملفات المحلية إذا لم تكن موجودة
function initializeLocalFiles() {
    const files = [
        'local-users.json',
        'local-messages.json', 
        'local-images.json'
    ];
    
    files.forEach(file => {
        if (!fs.existsSync(file)) {
            fs.writeFileSync(file, '[]');
            console.log(`✅ تم إنشاء ملف ${file}`);
        }
    });
    
    // إنشاء مجلد uploads إذا لم يكن موجوداً
    if (!fs.existsSync('uploads')) {
        fs.mkdirSync('uploads');
        console.log('✅ تم إنشاء مجلد uploads');
    }
}

// استدعاء الدالة لتهيئة الملفات
initializeLocalFiles();

// تكوين MongoDB - نستخدم قاعدة بيانات محلية
const MONGODB_URI = 'mongodb://localhost:27017/student-platform';

// محاولة الاتصال بقاعدة البيانات مع fallback للتخزين المحلي
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('✅ تم الاتصال بقاعدة البيانات المحلية بنجاح');
}).catch(err => {
    console.log('⚠️  استخدام التخزين المحلي بسبب:', err.message);
});

// نماذج البيانات
const UserSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    university: { type: String, required: true },
    major: { type: String, required: true },
    batch: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'student' }
}, { timestamps: true });

const MessageSchema = new mongoose.Schema({
    senderId: { type: String, required: true },
    senderName: { type: String, required: true },
    text: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

const ImageSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    userName: { type: String, required: true },
    imageName: { type: String, required: true },
    url: { type: String, required: true },
    sentAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Message = mongoose.model('Message', MessageSchema);
const Image = mongoose.model('Image', ImageSchema);

// تخزين محلي للصور
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        const phone = req.body.phone || 'unknown';
        // إزالة المسافات والأحرف الخاصة من اسم الملف
        const cleanName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '-');
        cb(null, `${phone}-${Date.now()}-${cleanName}`)
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB
    }
});

// Middleware المصادقة البسيطة
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'الوصول مرفوض' });
    }

    try {
        const user = jwt.verify(token, 'student-platform-secret-2024');
        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'رمز غير صالح' });
    }
};

// دوال مساعدة للتخزين المحلي
function readLocalFile(filename) {
    try {
        const data = fs.readFileSync(filename, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

function writeLocalFile(filename, data) {
    try {
        fs.writeFileSync(filename, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('Error writing to local file:', error);
        return false;
    }
}

// المسارات
app.post('/api/auth/register', async (req, res) => {
    try {
        const { fullName, phone, university, major, batch, password } = req.body;

        // التحقق من صحة رقم الهاتف السعودي
        const saudiPhoneRegex = /^5\d{8}$/;
        if (!saudiPhoneRegex.test(phone)) {
            return res.status(400).json({ 
                message: 'رقم الهاتف غير صحيح. يجب أن يبدأ بـ 5 ويتكون من 9 أرقام' 
            });
        }

        let existingUser;
        try {
            // محاولة استخدام MongoDB
            existingUser = await User.findOne({ phone });
        } catch (dbError) {
            // استخدام التخزين المحلي
            const users = readLocalFile('local-users.json');
            existingUser = users.find(u => u.phone === phone);
        }

        if (existingUser) {
            return res.status(400).json({ message: 'رقم الهاتف مسجل مسبقاً' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            _id: Date.now().toString(),
            fullName,
            phone,
            university,
            major,
            batch,
            password: hashedPassword,
            role: 'student',
            createdAt: new Date().toISOString()
        };

        try {
            // محاولة الحفظ في MongoDB
            const user = new User(newUser);
            await user.save();
        } catch (dbError) {
            // الحفظ في التخزين المحلي
            const users = readLocalFile('local-users.json');
            users.push(newUser);
            writeLocalFile('local-users.json', users);
        }

        res.status(201).json({ message: 'تم إنشاء الحساب بنجاح' });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { phone, password } = req.body;

        let user;
        try {
            // البحث في MongoDB
            user = await User.findOne({ phone });
        } catch (dbError) {
            // البحث في التخزين المحلي
            const users = readLocalFile('local-users.json');
            user = users.find(u => u.phone === phone);
        }

        if (!user) {
            return res.status(400).json({ message: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
        }

        const token = jwt.sign(
            { 
                _id: user._id || user.phone, 
                fullName: user.fullName,
                phone: user.phone,
                role: user.role 
            },
            'student-platform-secret-2024',
            { expiresIn: '30d' }
        );

        res.json({
            token,
            user: {
                _id: user._id || user.phone,
                fullName: user.fullName,
                phone: user.phone,
                university: user.university,
                major: user.major,
                batch: user.batch,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.post('/api/chat/send', authenticateToken, async (req, res) => {
    try {
        const { text } = req.body;

        const newMessage = {
            _id: Date.now().toString(),
            senderId: req.user._id,
            senderName: req.user.fullName,
            text,
            timestamp: new Date().toISOString()
        };

        try {
            // محاولة الحفظ في MongoDB
            const message = new Message(newMessage);
            await message.save();
        } catch (dbError) {
            // الحفظ في التخزين المحلي
            const messages = readLocalFile('local-messages.json');
            messages.push(newMessage);
            writeLocalFile('local-messages.json', messages);
        }

        // إرسال رد تلقائي من المدير بعد 2 ثانية
        setTimeout(async () => {
            const autoReplies = [
                'شكراً على رسالتك، كيف يمكنني مساعدتك؟',
                'تم استلام رسالتك، سنرد عليك قريباً',
                'أهلاً وسهلاً، هل تحتاج إلى مساعدة؟',
                'نقدر تواصلك معنا، سنحاول مساعدتك بأسرع وقت'
            ];
            
            const randomReply = autoReplies[Math.floor(Math.random() * autoReplies.length)];
            const adminMessage = {
                _id: Date.now().toString() + '-admin',
                senderId: 'admin',
                senderName: 'مدير النظام',
                text: randomReply,
                timestamp: new Date().toISOString()
            };

            try {
                const message = new Message(adminMessage);
                await message.save();
            } catch (dbError) {
                const messages = readLocalFile('local-messages.json');
                messages.push(adminMessage);
                writeLocalFile('local-messages.json', messages);
            }
        }, 2000);

        res.json({ message: 'تم إرسال الرسالة' });
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.get('/api/chat/messages', authenticateToken, async (req, res) => {
    try {
        let messages;
        try {
            messages = await Message.find().sort({ timestamp: 1 }).limit(50);
        } catch (dbError) {
            messages = readLocalFile('local-messages.json')
                .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
                .slice(-50);
        }
        res.json(messages);
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.post('/api/admin/send-image', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'غير مصرح بالوصول' });
        }

        const { phone } = req.body;

        if (!req.file) {
            return res.status(400).json({ message: 'لم يتم رفع أي صورة' });
        }

        let user;
        try {
            user = await User.findOne({ phone });
        } catch (dbError) {
            const users = readLocalFile('local-users.json');
            user = users.find(u => u.phone === phone);
        }

        if (!user) {
            return res.status(404).json({ message: `لم يتم العثور على مستخدم بالرقم: ${phone}` });
        }

        const imageUrl = `/uploads/${req.file.filename}`;
        const newImage = {
            _id: Date.now().toString(),
            userId: user._id || user.phone,
            userName: user.fullName,
            imageName: phone,
            url: imageUrl,
            sentAt: new Date().toISOString()
        };

        try {
            const image = new Image(newImage);
            await image.save();
        } catch (dbError) {
            const images = readLocalFile('local-images.json');
            images.push(newImage);
            writeLocalFile('local-images.json', images);
        }

        res.json({ 
            message: 'تم إرسال الصورة بنجاح', 
            image: {
                url: imageUrl,
                userName: user.fullName,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Send image error:', error);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.get('/api/images', authenticateToken, async (req, res) => {
    try {
        let images;
        try {
            images = await Image.find({ 
                userId: req.user._id 
            }).sort({ sentAt: -1 });
        } catch (dbError) {
            images = readLocalFile('local-images.json')
                .filter(img => img.userId === req.user._id)
                .sort((a, b) => new Date(b.sentAt) - new Date(a.sentAt));
        }
        
        res.json(images);
    } catch (error) {
        console.error('Get images error:', error);
        res.status(500).json({ message: 'خطأ في الخادم' });
    }
});

app.use('/uploads', express.static('uploads'));

// إنشاء مدير افتراضي
const createAdminUser = async () => {
    try {
        let adminExists;
        try {
            adminExists = await User.findOne({ role: 'admin' });
        } catch (dbError) {
            const users = readLocalFile('local-users.json');
            adminExists = users.find(u => u.role === 'admin');
        }

        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            const adminUser = {
                _id: 'admin-' + Date.now(),
                fullName: 'مدير النظام',
                phone: '500000000',
                university: 'الإدارة',
                major: 'الإدارة',
                batch: '2024',
                password: hashedPassword,
                role: 'admin',
                createdAt: new Date().toISOString()
            };

            try {
                const admin = new User(adminUser);
                await admin.save();
                console.log('✅ تم إنشاء حساب المدير في MongoDB');
            } catch (dbError) {
                const users = readLocalFile('local-users.json');
                users.push(adminUser);
                writeLocalFile('local-users.json', users);
                console.log('✅ تم إنشاء حساب المدير في التخزين المحلي');
            }
        } else {
            console.log('✅ حساب المدير موجود بالفعل');
        }
    } catch (error) {
        console.error('خطأ في إنشاء المدير:', error);
    }
};

// route الأساسي
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// مسار الصحة
app.get('/health', (req, res) => {
    res.json({ 
        status: '✅ الخادم يعمل بشكل طبيعي',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'MongoDB' : 'محلي'
    });
});

// مسار لتفريغ البيانات (للتطوير)
app.get('/api/debug/data', (req, res) => {
    const users = readLocalFile('local-users.json');
    const messages = readLocalFile('local-messages.json');
    const images = readLocalFile('local-images.json');
    
    res.json({
        users: users.length,
        messages: messages.length,
        images: images.length,
        database: mongoose.connection.readyState === 1 ? 'MongoDB' : 'محلي'
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
    console.log(`🌐 جاهز للاستخدام المحلي والسحابي`);
    console.log(`📊 حالة قاعدة البيانات: ${mongoose.connection.readyState === 1 ? 'MongoDB' : 'التخزين المحلي'}`);
    
    // إنشاء المدير بعد بدء التشغيل
    setTimeout(createAdminUser, 1000);
});