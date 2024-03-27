# errsole-sequelize
A Sequelize logging module for Node.js applications, designed to simplify the logging of information and errors into a database managed by Sequelize. This module provides a straightforward way to log messages from your Node.js applications and retrieve them for monitoring or debugging purposes
# Features
Easy integration with Node.js applications.
Configurable database connection using Sequelize.
Supports logging of information and error messages into relational databases.
Provides a function to retrieve all logs from the database for monitoring or debugging purposes.

# installation
```
npm install errsole-sequelize
```

# usage
First, ensure your relational database is running and accessible from your application. Then, follow these steps to integrate errsole-sequelize into your Node.js application

# initialization
In your main application file, initialize the errsole-sequelize module with the database connection details:
```javascript
const errsoleSequelize = require('errsole-sequelize');
const storage = new errsoleSequelize({
    host: 'localhost',
    username: 'username',
    password: 'password',
    database: 'myDatabase',
    dialect:'mysql', // Specify the type of database to connect to. This can be 'mysql', 'postgresql', 'sqlite', 'mssql', etc.
})
```
