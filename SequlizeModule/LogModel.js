const express = require('express');
const { saveErrorLog,saveInfoLog,getLogs } = require('../sequlize-logger');
const sequelize = require('./Sequlize');
const app = express();
const port = 3080;

sequelize.authenticate().then(() => {
    console.log('Connection has been established successfully.');
    return sequelize.sync(); 
}).catch(err => {
    console.error('Unable to connect to the database:', err);
});

app.use(async (req, res, next) => {
    await saveInfoLog(`Accessing from database ${req.path}`);
    next();
});


app.use((err, req, res, next) => {
    console.error(err); 
    saveErrorLog(`Error during request to ${req.path}: ${err.message}`);
    res.status(500).send('An internal server error occurred');
});

app.get('/logs', async (req, res) => {
    const { level } = req.query;
    const logs = await getLogs(level);
    res.json(logs);
});

app.listen(port, () => {
    console.log(`application listening http://localhost:${port}`);
});
