const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library'); // 🔒 ADD THIS
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// 🔒 SECURITY FIX: Allow your specific frontend ports (including Live Server)
app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500'], 
    credentials: true
}));
app.use(bodyParser.json());

// Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false // Only use SSL if configured
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
        return;
    }
    console.log('✅ Connected to MySQL Database');
});

// 🔒 SECURITY FIX: Initialize Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ==========================================
// AUTH ROUTES
// ==========================================

// 1. Email/Password Register (ONLY FIRST ADMIN - SECURED)
app.post('/api/auth/register', async (req, res) => {
    const { email, password, full_name } = req.body;
    if (!email || !password || !full_name) return res.status(400).json({ error: 'All fields are required' });

    // Check if any admin already exists
    db.query('SELECT COUNT(*) as count FROM admins', async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        const adminCount = results[0].count;

        // Block registration if admin exists
        if (adminCount > 0) {
            return res.status(403).json({ error: 'Access Denied: Only the Super Admin can create accounts. Please contact the Super Admin.' });
        }

        // Allow first admin registration
        db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (results.length > 0) return res.status(409).json({ error: 'Email already registered' });

            const hashedPassword = await bcrypt.hash(password, 10);
            const sql = "INSERT INTO admins (email, password, full_name, role) VALUES (?, ?, ?, 'SUPER_ADMIN')";
            db.query(sql, [email, hashedPassword, full_name], (err, result) => {
                if (err) return res.status(500).json({ error: 'Database error' });
                const token = jwt.sign({ id: result.insertId, email, full_name, role: 'SUPER_ADMIN' }, process.env.JWT_SECRET, { expiresIn: '1d' });
                res.status(201).json({ message: 'Admin registered successfully', token, admin: { id: result.insertId, email, full_name, role: 'SUPER_ADMIN' } });
            });
        });
    });
});

// 2. Email/Password Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

        const admin = results[0];
        const passwordMatch = await bcrypt.compare(password, admin.password || '');
        if (!passwordMatch) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign({ id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ token, admin: { id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role } });
    });
});

// 🔒 SECURITY FIX: Google OAuth Login (VERIFIED)
app.post('/api/auth/google', async (req, res) => {
    const { credential } = req.body;

    try {
        // Verify the Google token
        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, name, sub: googleId } = payload;

        // Check if admin exists
        db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ error: 'Database error' });

            if (results.length === 0) {
                // Create new admin if doesn't exist
                const sql = "INSERT INTO admins (email, full_name, role, google_id) VALUES (?, ?, 'ADMIN', ?)";
                db.query(sql, [email, name, googleId], (err, result) => {
                    if (err) return res.status(500).json({ error: 'Database error' });
                    const token = jwt.sign({ id: result.insertId, email, full_name: name, role: 'ADMIN' }, process.env.JWT_SECRET, { expiresIn: '1d' });
                    res.status(201).json({ token, admin: { id: result.insertId, email, full_name: name, role: 'ADMIN' } });
                });
            } else {
                // Existing admin - login
                const admin = results[0];
                const token = jwt.sign({ id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
                res.status(200).json({ token, admin: { id: admin.id, email: admin.email, full_name: admin.full_name, role: admin.role } });
            }
        });
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(401).json({ error: 'Invalid Google token' });
    }
});

// 3. Get Current User (Auth Middleware)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// SUPER ADMIN CHECK MIDDLEWARE
const requireSuperAdmin = (req, res, next) => {
    if (req.user.role !== 'SUPER_ADMIN') {
        return res.status(403).json({ error: 'Access Denied: Super Admin privileges required.' });
    }
    next();
};

app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// ==========================================
// ADMIN MANAGEMENT ROUTES (SUPER ADMIN ONLY)
// ==========================================

// 1. GET all admins (Super Admin only)
app.get('/api/admins', authenticateToken, requireSuperAdmin, (req, res) => {
    const sql = "SELECT id, email, full_name, role, created_at FROM admins";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.status(200).json(results);
    });
});

// 2. CREATE a new admin (Super Admin only)
app.post('/api/admins', authenticateToken, requireSuperAdmin, async (req, res) => {
    const { email, password, full_name, role } = req.body;
    if (!email || !password || !full_name) {
        return res.status(400).json({ error: 'Email, password, and full name required' });
    }

    db.query('SELECT * FROM admins WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (results.length > 0) return res.status(409).json({ error: 'Admin with this email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const finalRole = role === 'SUPER_ADMIN' ? 'SUPER_ADMIN' : 'ADMIN';
        const sql = "INSERT INTO admins (email, password, full_name, role) VALUES (?, ?, ?, ?)";
        db.query(sql, [email, hashedPassword, full_name, finalRole], (err, result) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.status(201).json({ message: 'Admin added successfully', id: result.insertId });
        });
    });
});

// 3. UPDATE admin role (Super Admin only)
app.put('/api/admins/:id/role', authenticateToken, requireSuperAdmin, (req, res) => {
    const { role } = req.body;
    if (!['SUPER_ADMIN', 'ADMIN'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }
    const sql = "UPDATE admins SET role = ? WHERE id = ?";
    db.query(sql, [role, req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Admin not found' });
        res.json({ message: 'Role updated successfully' });
    });
});

// 4. DELETE an admin (Super Admin only)
app.delete('/api/admins/:id', authenticateToken, requireSuperAdmin, (req, res) => {
    const sql = "DELETE FROM admins WHERE id = ?";
    db.query(sql, [req.params.id], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Admin not found' });
        res.json({ message: 'Admin deleted successfully' });
    });
});

// ==========================================
// BOOKING ROUTES (🔒 NOW SECURED WITH AUTH)
// ==========================================

// 1. Create a new booking (PUBLIC - customers can book)
app.post('/api/bookings', (req, res) => {
    const {
        full_name, phone, email, service_address, service_type, area_size, 
        price_per_sqm, total_price, preferred_date, preferred_time, payment_method, notes
    } = req.body;

    if (!full_name || !phone || !email || !service_address || !service_type || !preferred_date) {
        return res.status(400).json({ success: false, message: "Missing required fields." });
    }

    const sql = `
        INSERT INTO bookings 
        (full_name, phone, email, service_address, service_type, area_size, price_per_sqm, total_price, preferred_date, preferred_time, payment_method, notes) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const values = [full_name, phone, email, service_address, service_type, area_size, price_per_sqm, total_price, preferred_date, preferred_time, payment_method, notes || null];

    db.query(sql, values, (err, result) => {
        if (err) {
            console.error("Error saving booking:", err);
            return res.status(500).json({ success: false, message: "Database error", error: err.message });
        }
        res.status(201).json({ success: true, message: "Booking submitted successfully!", bookingId: result.insertId });
    });
});

// 🔒 FIX: All below routes now require authentication

// 2. Get all bookings (ADMIN ONLY)
app.get('/api/bookings', authenticateToken, (req, res) => {
    const sql = "SELECT id, full_name, phone, email, service_address, service_type, area_size, price_per_sqm, total_price, preferred_date, preferred_time, payment_method, payment_status, payment_reference, booking_status, notes, created_at FROM bookings ORDER BY created_at DESC";
    db.query(sql, (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Error fetching data" });
        res.status(200).json(result);
    });
});

// 3. Get single booking by ID (ADMIN ONLY)
app.get('/api/bookings/:id', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const sql = "SELECT * FROM bookings WHERE id = ?";
    db.query(sql, [bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Error fetching data" });
        if (result.length === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        res.status(200).json(result[0]);
    });
});

// 4. Update booking status (ADMIN ONLY)
app.put('/api/bookings/:id/status', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const { booking_status } = req.body;
    const allowedStatuses = ['PENDING', 'CONFIRMED', 'COMPLETED', 'CANCELLED'];
    if (!allowedStatuses.includes(booking_status)) {
        return res.status(400).json({ success: false, message: "Invalid booking status" });
    }
    const sql = "UPDATE bookings SET booking_status = ? WHERE id = ?";
    db.query(sql, [booking_status, bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        const selectSql = "SELECT * FROM bookings WHERE id = ?";
        db.query(selectSql, [bookingId], (err, rows) => {
            if (err) return res.status(500).json({ success: false, message: "Error fetching updated booking" });
            res.status(200).json({ success: true, message: "Booking status updated successfully", booking: rows[0] });
        });
    });
});

// 5. Update payment status (ADMIN ONLY)
app.put('/api/bookings/:id/payment', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const { payment_status } = req.body;
    const allowedStatuses = ['PENDING', 'PAID', 'REFUNDED', 'FAILED'];
    if (!allowedStatuses.includes(payment_status)) {
        return res.status(400).json({ success: false, message: "Invalid payment status" });
    }
    const sql = "UPDATE bookings SET payment_status = ? WHERE id = ?";
    db.query(sql, [payment_status, bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        const selectSql = "SELECT * FROM bookings WHERE id = ?";
        db.query(selectSql, [bookingId], (err, rows) => {
            if (err) return res.status(500).json({ success: false, message: "Error fetching updated booking" });
            res.status(200).json({ success: true, message: "Payment status updated successfully", booking: rows[0] });
        });
    });
});

// 6. Delete a booking (ADMIN ONLY)
app.delete('/api/bookings/:id', authenticateToken, (req, res) => {
    const bookingId = req.params.id;
    const sql = "DELETE FROM bookings WHERE id = ?";
    db.query(sql, [bookingId], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error" });
        if (result.affectedRows === 0) return res.status(404).json({ success: false, message: "Booking not found" });
        res.status(200).json({ success: true, message: "Booking deleted successfully" });
    });
});

// Start the Server
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});