const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const secretKey = 'your-secret-key';

app.use(bodyParser.json());

// Mock database
const users = [];

// Signup route
app.post('/signup', (req, res) => {
    console.log("Alo")
  const { username, password } = req.body;
  // Check if the user already exists
  if (users.find(user => user.username === username)) {
    return res.status(409).json({ error: 'User already exists' });
  }
  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Internal server error' });
    }
    // Store the user in the database
    users.push({ username, password: hashedPassword });
    res.status(201).json({ message: 'User created successfully' });
  });
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Find the user in the database
  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  // Compare passwords
  bcrypt.compare(password, user.password, (err, result) => {
    if (err || !result) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    // Create a JWT
    const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Protected route example
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route accessed successfully' });
});

// Middleware to verify the token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = decoded;
    next();
  });
}

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
