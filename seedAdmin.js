// backend/seedAdmin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User');

const MONGO = process.env.MONGODB_URI || 'mongodb://localhost:27017/rbfinance';
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;

async function run() {
    await mongoose.connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Connected to DB');

    const adminEmail = process.env.ADMIN_EMAIL || 'admin@rb-finance.local';
    const adminPass = process.env.ADMIN_PASS || 'AdminPass123!';
    const username = process.env.ADMIN_USERNAME || 'admin';

    const existing = await User.findOne({ email: adminEmail }).lean();
    if (existing) {
        console.log('Admin already exists:', adminEmail);
        process.exit(0);
    }

    const passwordHash = await bcrypt.hash(adminPass, SALT_ROUNDS);
    const pinHash = await bcrypt.hash('0000', SALT_ROUNDS);

    // generate simple static admin account number (safe for demo)
    const accountNumber = process.env.ADMIN_ACCOUNT || '80000000000';

    const admin = new User({
        firstName: 'RB',
        lastName: 'Admin',
        username,
        email: adminEmail.toLowerCase(),
        phone: '+0000000000',
        country: 'N/A',
        accountType: 'admin',
        accountNumber,
        password: passwordHash,
        pin: pinHash,
        active: true,
        role: 'admin',
        isAdmin: true,
        balance: 0
    });

    await admin.save();
    console.log('Admin created: ', adminEmail, ' password:', adminPass);
    process.exit(0);
}

run().catch(err => { console.error(err); process.exit(1); });
