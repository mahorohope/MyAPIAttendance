const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false })); 
app.use(bodyParser.json()); 
app.use(express.json());
const port = 3306; //change from to 3306

// Database credentials
const pool = mysql.createPool({
  host: 'bmie07s6tnxmkbfkea0m-mysql.services.clever-cloud.com',
  user: 'ujdotni2gyesgkhl',
  password: 'ROzSVzS0Tbd5hq6rYoWw',
  database: 'bmie07s6tnxmkbfkea0m'
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Unauthorized access: Token missing');
  jwt.verify(token.replace('Bearer ', ''), 'secret_key', (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).send('Unauthorized access: Invalid or expired token');
    }
    req.userId = decoded.id;
    next();
  });
};

// Get all data from a roles table
app.get('/roles',verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM roles');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving roles');
  }
});

// Select Single role
app.get('/roles/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.query('SELECT * FROM roles WHERE id = ?', [id]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error showing role');
  }
});

// Insert data into roles table
app.post('/roles', verifyToken, async (req, res) => {
  const { role_name } = req.body; // Destructure data from request body
  if (!role_name) {
    return res.status(400).send('Please provide all required field (Role Name )');
  }
  try {
    const [result] = await pool.query('INSERT INTO roles SET ?', { role_name });
    res.json({ message: `role inserted successfully with ID: ${result.insertId}` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error inserting role');
  }
});

// Update role
app.put('/roles/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const { role_name } = req.body; // Destructure data from request body
  if (!role_name) {
    return res.status(400).send('Please provide all required fields ( role_name)');
  }
  try {
    const [result] = await pool.query('UPDATE roles SET role_name = ? WHERE id = ?', [role_name, id]);
    res.json({ message: `Role Details updated successfully with ID: ${req.params.id}` });  // Use ID from request params
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating role');
  }
});

// Delete role using id
app.delete('/roles/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM roles WHERE id = ?', [id]);
    res.json({ message: `Data with ID ${id} deleted successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting role');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!users.length) {
      return res.status(404).send('User not found');
    }

    const user = users[0];
    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Invalid password');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id }, 'secret_key', { expiresIn: '1h' });

    // Send the token as response
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
    res.status(200).send('loggen success');
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
