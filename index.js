const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const users = require('./users');
const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// Катталуу
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    res.json({ message: 'Катталдың!' });
});

// Кирүү
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(401).json({ message: 'Колдонуучу табылган жок' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Ката пароль' });

    const token = jwt.sign({ username }, process.env.JWT_SECRET);
    res.json({ token });
});

// Корголгон API
app.get('/profile', authMiddleware, (req, res) => {
    res.json({ message: `Салам, ${req.user.username}` });
});

// Middleware
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'JWT керек' });

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Токен жараксыз' });
    }
}

app.listen(PORT, () => {
    console.log(`Сервер иштеп жатат: http://localhost:${PORT}`);
});
