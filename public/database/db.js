require('dotenv').config();
const { Pool } = require('pg');


const pool = new Pool({
    user: process.env.DB_USER,       
    host: process.env.DB_HOST,       
    database: process.env.DB_NAME,   
    password: process.env.DB_PASSWORD, 
    port: process.env.DB_PORT,  
});

const createTable = async () => {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                email VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(100) NOT NULL
            );
        `);
        console.log('Table "users" created or already exists.');
    } catch (err) {
        console.error('Error creating table', err);
    } finally {
        client.release();
    }
};


const createTable3 = async () => {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id SERIAL PRIMARY KEY,
                token VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL,
                used BOOLEAN DEFAULT FALSE
            );
        `);
        console.log('Table "password_reset_tokens" created or already exists.');
    } catch (err) {
        console.error('Error creating table', err);
    } finally {
        client.release();
    }
};



createTable();
createTable3();

module.exports = pool;

