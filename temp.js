const { Client } = require('pg');

// PostgreSQL Connection
const client = new Client({
    user: 'postgres',
    host: 'localhost',
    database: 'next_auth',
    password: 'alok@1234',
    port: 5432,
});

async function fetchData() {
    try {
        await client.connect(); // Connect to PostgreSQL
        console.log('Connected to PostgreSQL');

        const result = await client.query('SELECT * FROM users'); // Fetch all users
        console.log('Users:', result.rows); // Print data

    } catch (error) {
        console.error('Error fetching data:', error);
    } finally {
        await client.end(); // Close connection
        console.log('Connection closed');
    }
}

fetchData();
