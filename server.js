const http = require('http');
const { Client } = require('pg');
const qs = require('querystring');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const formidable = require('formidable');
const Razorpay = require('razorpay');
const PORT = process.env.PORT || 3000; // Use Render's PORT if available

const client = new Client({
 //  user: 'root',
 //  host: 'dpg-cv4k5c0fnakc73bovokg-a',
 //  database: 'next_auth_65sq',
 //  password: 'WWD4LlFkKzyt2WfWhTjIRWox60f8EtiX',
 //  port: 5432,
//
  user: 'postgres',
  host: 'localhost',
  database: 'next_auth',
  password: 'alok@1234',
  port: 5432,
});





client.connect()
    .then(() => console.log('Connected to PostgreSQL database'))
    .catch(err => console.error('Database connection error:', err.stack));

const razorpay = new Razorpay({
    key_id: "YOUR_RAZORPAY_KEY", // Replace with your Razorpay Key ID
    key_secret: "YOUR_RAZORPAY_SECRET" // Replace with your Razorpay Secret
});

const uploadDir = path.join(__dirname, 'profile_images');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Function to set CORS headers for all origins
const setCorsHeaders = (res) => {
    res.setHeader('Access-Control-Allow-Origin', '*'); // Allow all origins
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
};



// Function to check and create the `users` table
const checkAndCreateUsersTable = async () => {
    const tableCheck = await client.query(
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'users';"
    );

    if (tableCheck.rowCount === 0) {
        console.log("Table 'users' does not exist. Creating...");
        const createTableQuery = `
            CREATE TABLE public.users (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(100) NOT NULL,
                email VARCHAR(100) NOT NULL UNIQUE,
                password TEXT NOT NULL,
                dob DATE NOT NULL,
                sex VARCHAR(10) NOT NULL,
                country VARCHAR(50) NOT NULL,
                mobile VARCHAR(20) NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                participant_address TEXT DEFAULT 'No Address',
                payment_status VARCHAR(50) DEFAULT 'Not Paid',
                payment_amount NUMERIC(10,2) DEFAULT 0.00,
                profile_image TEXT
            );
        `;
        await client.query(createTableQuery);
        console.log("Table 'users' created successfully.");
    } else {
        console.log("Table 'users' already exists.");
    }
};

// Function to check and create the `events` table
const checkAndCreateEventsTable = async () => {
    const tableCheck = await client.query(
        "SELECT 1 FROM information_schema.tables WHERE table_name = 'events';"
    );

    if (tableCheck.rowCount === 0) {
        console.log("Table 'events' does not exist. Creating...");
        const createTableQuery = `
            CREATE TABLE public.events (
                id SERIAL PRIMARY KEY,
                reporting_time TIME NOT NULL,
                event_start_time TIME NOT NULL,
                organization_name VARCHAR(255) NOT NULL,
                event_location TEXT NOT NULL,
                authorized_by VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIME
            );
        `;
        await client.query(createTableQuery);
        console.log("Table 'events' created successfully.");
    } else {
        console.log("Table 'events' already exists.");
    }
};

// Main function to set up the tables
const setupTables = async () => {
    try {
        await checkAndCreateUsersTable();
        await checkAndCreateEventsTable();
    } catch (err) {
        console.error("Error setting up tables:", err);
    }
};

setupTables();

const server = http.createServer(async (req, res) => {
    // Apply CORS headers to all responses
    setCorsHeaders(res);

    // Log every incoming request for debugging
    console.log(`Request received: ${req.method} ${req.url}`);

    // Handle CORS preflight OPTIONS requests
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        console.log('Handled OPTIONS preflight request');
        return;
    }

    if (req.method === 'POST' && req.url === '/update-address') {
        const cookies = parseCookies(req);
        const userId = cookies.user_id;

        if (!userId) {
            console.log('No user_id cookie found');
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'User not logged in' }));
            return;
        }

        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const data = qs.parse(body);
                const newAddress = data.address;

                if (!newAddress || newAddress.trim() === '') {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Address is required' }));
                    return;
                }

                const userResult = await client.query(
                    'SELECT full_name, email, profile_image FROM users WHERE id = $1',
                    [userId]
                );

                const fullName = userResult.rows[0]?.full_name || 'Unknown';
                const userEmail = userResult.rows[0]?.email || 'Unknown';
                const profileImage = userResult.rows[0]?.profile_image || '/api/placeholder/150/150';

                await client.query(
                    'UPDATE users SET participant_address = $1 WHERE id = $2',
                    [newAddress, userId]
                );

                console.log(`Address updated for user ${userId} (Name: ${fullName}, Email: ${userEmail}, Image: ${profileImage}): ${newAddress}`);
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true }));
            } catch (err) {
                console.error('Error updating address:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Database error', details: err.message }));
            }
        });
    }

    // Handle POST /forgot-password
    else if (req.method === 'POST' && req.url === '/forgot-password') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const data = qs.parse(body);
                const { email, mobile } = data;

                if (!email || !mobile) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Email and mobile are required' }));
                    return;
                }

                const result = await client.query(
                    'SELECT id FROM users WHERE email = $1 AND mobile = $2',
                    [email, mobile]
                );

                if (result.rows.length > 0) {
                    const token = crypto.randomBytes(20).toString('hex');
                    await client.query(
                        'UPDATE users SET reset_token = $1, reset_token_expiry = NOW() + INTERVAL \'1 hour\' WHERE email = $2',
                        [token, email]
                    );

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: 'Validation successful. Enter new password.' }));
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Email or mobile not found' }));
                }
            } catch (err) {
                console.error('Error in forgot-password:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Server error', details: err.message }));
            }
        });
    }

    // Handle POST /verify-mobile
    else if (req.method === 'POST' && req.url === '/verify-mobile') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const data = qs.parse(body);
                const { email, mobile } = data;

                if (!email || !mobile) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        mobileVerified: false,
                        message: 'Email and mobile number are required' 
                    }));
                    return;
                }

                const result = await client.query(
                    'SELECT mobile FROM users WHERE email = $1',
                    [email]
                );

                if (result.rows.length === 0) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        mobileVerified: false,
                        message: 'Email not found' 
                    }));
                    return;
                }

                const storedMobile = result.rows[0].mobile;
                if (storedMobile !== mobile) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        mobileVerified: false,
                        message: 'Mobile number does not match the email' 
                    }));
                    return;
                }

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true, 
                    mobileVerified: true,
                    message: 'Mobile number verified' 
                }));
            } catch (err) {
                console.error('Error in verify-mobile:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: false, 
                    mobileVerified: false,
                    message: 'Server error occurred', 
                    details: err.message 
                }));
            }
        });
    }

    // Handle POST /reset-password
    else if (req.method === 'POST' && req.url === '/reset-password') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const data = qs.parse(body);
                const { email, mobile, newPassword } = data;

                if (!email || !mobile || !newPassword) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        message: 'Email, mobile number, and new password are required' 
                    }));
                    return;
                }

                const userResult = await client.query(
                    'SELECT id FROM users WHERE email = $1 AND mobile = $2',
                    [email, mobile]
                );

                if (userResult.rows.length === 0) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        message: 'Email and mobile number combination is invalid' 
                    }));
                    return;
                }

                const hashedPassword = crypto.createHash('sha256')
                    .update(newPassword)
                    .digest('hex');

                const updateResult = await client.query(
                    'UPDATE users SET password = $1 WHERE email = $2 AND mobile = $3 RETURNING id',
                    [hashedPassword, email, mobile]
                );

                if (updateResult.rows.length > 0) {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: true, 
                        message: 'Password has been reset successfully' 
                    }));
                } else {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false, 
                        message: 'Failed to reset password' 
                    }));
                }
            } catch (err) {
                console.error('Error in reset-password:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: false, 
                    message: 'Server error occurred', 
                    details: err.message 
                }));
            }
        });
    }

    else if (req.method === 'POST' && req.url === '/upload-photo') {
        const cookies = parseCookies(req);
        const userId = cookies.user_id;

        if (!userId) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'User not logged in' }));
            return;
        }

        const form = new formidable.IncomingForm({
            uploadDir: uploadDir,
            keepExtensions: true,
            maxFileSize: 5 * 1024 * 1024
        });

        try {
            const [fields, files] = await form.parse(req);
            const file = files.photo?.[0];

            if (!file) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'No file uploaded' }));
                return;
            }

            const validTypes = ['image/jpeg', 'image/png', 'image/gif'];
            if (!validTypes.includes(file.mimetype)) {
                await fs.promises.unlink(file.filepath);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'Invalid file type. Only JPG, PNG, and GIF allowed' }));
                return;
            }

            const newFilename = `${userId}-${Date.now()}${path.extname(file.originalFilename || '.jpg')}`;
            const newPath = path.join(uploadDir, newFilename);

            await fs.promises.rename(file.filepath, newPath);

            await client.query(
                'UPDATE users SET profile_image = $1 WHERE id = $2',
                [`/profile_images/${newFilename}`, userId]
            );

            console.log(`Image uploaded for user ${userId}: /profile_images/${newFilename}`);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ 
                success: true, 
                imageUrl: `/profile_images/${newFilename}` 
            }));
        } catch (err) {
            console.error('Error in upload-photo:', err.stack);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: 'Upload error', details: err.message }));
        }
    }

    else if (req.method === 'GET') {
        if (req.url.startsWith('/checkEmail')) {
            const urlParams = new URL(req.url, `http://${req.headers.host}`);
            const email = urlParams.searchParams.get('email');

            if (!email) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Email is required' }));
                return;
            }

            try {
                const result = await client.query('SELECT 1 FROM users WHERE email = $1', [email]);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ exists: result.rows.length > 0 }));
            } catch (err) {
                console.error('Error in checkEmail:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Database error', details: err.message }));
            }
        }
        else if (req.url.startsWith('/checkMobile')) {
            const urlParams = new URL(req.url, `http://${req.headers.host}`);
            const mobile = urlParams.searchParams.get('mobile');

            if (!mobile) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Mobile number is required' }));
                return;
            }

            try {
                const result = await client.query('SELECT 1 FROM users WHERE mobile = $1', [mobile]);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ exists: result.rows.length > 0 }));
            } catch (err) {
                console.error('Error in checkMobile:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Database error', details: err.message }));
            }
        }
        else if (req.url === '/getEvent') {
            const cookies = parseCookies(req);
            const userId = cookies.user_id;

            if (!userId) {
                console.log('No user_id cookie found');
                res.writeHead(401, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'User not logged in' }));
                return;
            }

            try {
                const userResult = await client.query(
                    `SELECT full_name AS participant_name, email, participant_address, payment_status, payment_amount, profile_image
                     FROM users
                     WHERE id = $1`,
                    [userId]
                );
                console.log("User Query Result:", userResult.rows);

                const eventResult = await client.query(
                    `SELECT reporting_time, event_start_time, end_time, organization_name, event_location, authorized_by
                     FROM events
                     LIMIT 1`
                );
                console.log("Event Query Result:", eventResult.rows);

                if (userResult.rows.length > 0) {
                    const userData = userResult.rows[0];
                    const eventData = eventResult.rows.length > 0 ? eventResult.rows[0] : {};
                    
                    const formatTime = (time) => {
                        if (!time) return 'N/A';
                        if (time instanceof Date) return time.toLocaleTimeString();
                        const date = new Date(time);
                        return isNaN(date.getTime()) ? time : date.toLocaleTimeString();
                    };
                    
                    const responseData = {
                        participant_name: userData.participant_name || 'Unknown Participant',
                        email: userData.email || '',
                        participant_address: userData.participant_address || 'No Address',
                        reporting_time: formatTime(eventData.reporting_time) || '08:30 AM',
                        event_start_time: formatTime(eventData.event_start_time) || '09:00 AM',
                        end_time: formatTime(eventData.end_time) || '13:00 PM',
                        organization_name: eventData.organization_name || 'Tech Innovators Association',
                        event_location: eventData.event_location || 'Grand Convention Center, San Francisco, CA 94103',
                        authorized_by: eventData.authorized_by || 'Event Coordinator',
                        payment_status: userData.payment_status || 'Not Paid',
                        payment_amount: userData.payment_amount || 0.00,
                        profile_image: userData.profile_image || '/api/placeholder/150/150'
                    };
                    console.log("Response Data:", responseData);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(responseData));
                } else {
                    console.log(`No user found for user_id: ${userId}`);
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'No user found' }));
                }
            } catch (err) {
                console.error('Error in getEvent:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Database error', details: err.message }));
            }
        }
        else if (req.url === '/logout') {
            res.writeHead(302, {
                'Content-Type': 'text/plain',
                'Set-Cookie': 'user_id=; Max-Age=0; HttpOnly; Path=/',
                'Location': '/login.html'
            });
            res.end('Logging out and redirecting to login page...');
        }
        else if (req.url.startsWith('/profile_images/')) {
            const filePath = path.join(__dirname, req.url);
            try {
                const data = await fs.promises.readFile(filePath);
                res.writeHead(200, { 'Content-Type': getContentType(filePath) });
                res.end(data);
            } catch (err) {
                console.error('Error serving image:', err.stack);
                res.writeHead(404);
                res.end('Image not found');
            }
        }
        else {
            let filePath = req.url === '/' ? './login.html' : `.${req.url}`;
            if (req.url === '/sphere.html') {
                filePath = './sphere.html';
            }

            try {
                const data = await fs.promises.readFile(filePath);
                res.writeHead(200, { 'Content-Type': getContentType(filePath) });
                res.end(data);
            } catch (err) {
                res.writeHead(404);
                res.end('File not found');
            }
        }
    }

    else if (req.method === 'POST' && req.url === '/signup') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const data = qs.parse(body);
                if (!data.fullName || !data.email || !data.password || !data.mobile) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Missing required fields' }));
                    return;
                }

                const hashedPassword = crypto.createHash('sha256').update(data.password).digest('hex');

                const emailExists = await client.query('SELECT 1 FROM users WHERE email = $1', [data.email]);
                const mobileExists = await client.query('SELECT 1 FROM users WHERE mobile = $1', [data.mobile]);

                if (emailExists.rows.length > 0) {
                    res.writeHead(409, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Email already registered' }));
                    return;
                }

                if (mobileExists.rows.length > 0) {
                    res.writeHead(409, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Mobile number already registered' }));
                    return;
                }

                await client.query(
                    `INSERT INTO users (full_name, email, password, dob, sex, country, mobile, participant_address, payment_status, payment_amount, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, 'No Address', 'Not Paid', 0.00, NOW())`,
                    [data.fullName, data.email, hashedPassword, data.dob, data.sex, data.country, data.mobile]
                );

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, message: 'Signup successful!' }));
            } catch (err) {
                console.error('Error in signup:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Server error', details: err.message }));
            }
        });
    }

    else if (req.method === 'POST' && req.url === '/login') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const data = qs.parse(body);
                if (!data.email || !data.password) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Missing email or password' }));
                    return;
                }

                const hashedPassword = crypto.createHash('sha256').update(data.password).digest('hex');

                const result = await client.query(
                    `SELECT id, full_name FROM users WHERE email = $1 AND password = $2`,
                    [data.email, hashedPassword]
                );

                if (result.rows.length > 0) {
                    res.writeHead(200, {
                        'Content-Type': 'application/json',
                        'Set-Cookie': `user_id=${result.rows[0].id}; HttpOnly; Path=/`
                    });
                    res.end(JSON.stringify({ success: true, full_name: result.rows[0].full_name }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Invalid email or password' }));
                }
            } catch (err) {
                console.error('Error in login:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Server error', details: err.message }));
            }
        });
    }

    else if (req.method === 'POST' && req.url === '/verify-payment') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const data = qs.parse(body);
                const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = data;

                if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Missing required payment details' }));
                    return;
                }

                const expectedSignature = crypto.createHmac('sha256', "YOUR_RAZORPAY_SECRET")
                    .update(razorpay_order_id + "|" + razorpay_payment_id)
                    .digest('hex');

                if (expectedSignature === razorpay_signature) {
                    const cookies = parseCookies(req);
                    const userId = cookies.user_id;

                    if (userId) {
                        await client.query(
                            'UPDATE users SET payment_status = $1, payment_amount = $2 WHERE id = $3',
                            ['Paid', 500.00, userId]
                        );
                        console.log(`Payment verified and updated for user ${userId}`);
                    }

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: 'Payment verified successfully' }));
                } else {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Payment verification failed' }));
                }
            } catch (err) {
                console.error('Error in verify-payment:', err.stack);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Server error', details: err.message }));
            }
        });
    }

    else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));

function parseCookies(req) {
    const list = {};
    const cookieHeader = req.headers.cookie;
    if (!cookieHeader) return list;

    cookieHeader.split(';').forEach(cookie => {
        const [name, value] = cookie.split('=').map(c => c.trim());
        list[name] = value;
    });

    return list;
}

function getContentType(filePath) {
    if (filePath.endsWith('.html')) return 'text/html';
    if (filePath.endsWith('.css')) return 'text/css';
    if (filePath.endsWith('.js')) return 'application/javascript';
    if (filePath.endsWith('.png')) return 'image/png';
    if (filePath.endsWith('.jpg') || filePath.endsWith('.jpeg')) return 'image/jpeg';
    return 'text/plain';
}