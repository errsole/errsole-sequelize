/**
 * @typedef {Object} Log
 * @property {number} [id]
 * @property {string} hostname
 * @property {number} pid
 * @property {string} source
 * @property {Date} timestamp
 * @property {string} level
 * @property {string} message
 * @property {string} [meta]
 */

/**
 * @typedef {Object} LogFilter
 * @property {string} [hostname]
 * @property {number} [pid]
 * @property {{source: string, level: string}[]} [level_json]
 * @property {string[]} [sources]
 * @property {string[]} [levels]
 * @property {number} [lt_id]
 * @property {number} [gt_id]
 * @property {Date} [lte_timestamp]
 * @property {Date} [gte_timestamp]
 * @property {number} [limit=100]
 */

/**
 * @typedef {Object} Config
 * @property {number} id
 * @property {string} key
 * @property {string} value
 */

/**
 * @typedef {Object} User
 * @property {number} id
 * @property {string} name
 * @property {string} email
 * @property {string} role
 */

const bcrypt = require('bcryptjs');
const { EventEmitter } = require('events');
const { Sequelize, DataTypes } = require('sequelize');

const packageJSON = require('../package.json');

class ErrsoleSequelize extends EventEmitter {
  /**
   * Constructs an instance of the database handler using Sequelize.
   * This constructor initializes the Sequelize instance and sets up the database models and synchronization.
   * @param {Object} options - Configuration options for the Sequelize connection,
   * as described in the Sequelize documentation: https://sequelize.org/api/v6/class/src/sequelize.js~sequelize
   */
  constructor (options = {}) {
    super();
    if (!options.logging) options.logging = false;

    this.name = packageJSON.name;
    this.version = packageJSON.version || '0.0.0';
    this.dialect = options.dialect;

    this.sequelize = new Sequelize(options);
    this.isConnectionInProgress = true;
    this.defineModels();
    this.syncModels();
  }

  async defineModels () {
    this.errsoleLogs = this.sequelize.define('ErrsoleLogs', {
      id: {
        type: DataTypes.BIGINT,
        primaryKey: true,
        autoIncrement: true
      },
      hostname: DataTypes.STRING,
      pid: DataTypes.INTEGER,
      source: DataTypes.STRING,
      timestamp: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      },
      level: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'info'
      },
      message: DataTypes.TEXT,
      meta: DataTypes.TEXT
    }, {
      tableName: 'errsole_logs',
      timestamps: false,
      indexes: [
        { fields: ['source', 'level', 'id'] },
        { fields: ['source', 'level', 'timestamp'] },
        { fields: ['hostname', 'pid', 'id'] }
      ]
    });

    this.errsoleUsers = this.sequelize.define('ErrsoleUsers', {
      id: {
        type: DataTypes.BIGINT,
        primaryKey: true,
        autoIncrement: true
      },
      name: DataTypes.STRING,
      email: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false,
        validate: { isEmail: { msg: 'Invalid email format' } }
      },
      hashedPassword: {
        field: 'hashed_password',
        type: DataTypes.STRING,
        allowNull: false,
        validate: { notEmpty: { msg: 'Password cannot be empty' } }
      },
      role: {
        type: DataTypes.STRING,
        allowNull: false
      }
    }, {
      tableName: 'errsole_users',
      timestamps: false
    });

    this.errsoleConfig = this.sequelize.define('ErrsoleConfig', {
      id: {
        type: DataTypes.BIGINT,
        primaryKey: true,
        autoIncrement: true
      },
      key: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
      },
      value: {
        type: DataTypes.STRING,
        allowNull: false
      }
    }, {
      tableName: 'errsole_config',
      freezeTableName: true,
      timestamps: false
    });
  }

  async syncModels () {
    await this.sequelize.authenticate();
    await this.sequelize.sync();
    try {
      const queryInterface = this.sequelize.getQueryInterface();
      await queryInterface.removeIndex('errsole_logs', 'errsole_logs_message');
      await queryInterface.addIndex('errsole_logs', ['timestamp']);
    } catch {}
    await this.ensureLogsTTL();
    await this.setBufferSizes();
    this.isConnectionInProgress = false;
    this.emit('ready');
  }

  /**
   * Retrieves a configuration entry from the database.
   *
   * @async
   * @function getConfig
   * @param {string} key - The key of the configuration entry to retrieve.
   * @returns {Promise<{item: Config}>} - A promise that resolves with an object containing the configuration item.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getConfig (key) {
    const result = await this.errsoleConfig.findOne({ where: { key } });
    if (!result) return {};
    return { item: result.dataValues };
  }

  /**
   * Updates or adds a configuration entry in the database.
   *
   * @async
   * @function setConfig
   * @param {string} key - The key of the configuration entry.
   * @param {string} value - The value to be stored for the configuration entry.
   * @returns {Promise<{item: Config}>} - A promise that resolves with an object containing the updated or added configuration item.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async setConfig (key, value) {
    await this.errsoleConfig.upsert({ key, value });
    const result = await this.errsoleConfig.findOne({ where: { key } });
    if (!result) return {};
    return { item: result.dataValues };
  }

  /**
   * Deletes a configuration entry from the database.
   *
   * @async
   * @function deleteConfig
   * @param {string} key - The key of the configuration entry to be deleted.
   * @returns {Promise<{}>} - A Promise that resolves with an empty object upon successful deletion of the configuration.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async deleteConfig (key) {
    const result = await this.errsoleConfig.findOne({ where: { key } });
    if (!result) throw new Error('Configuration not found.');

    await result.destroy();

    return {};
  }

  /**
   * Adds log entries to the database.
   *
   * @async
   * @function postLogs
   * @param {Log[]} logEntries - An array of log entries to be added to the database.
   * @returns {Promise<{}>} - A Promise that resolves with an empty object.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async postLogs (logEntries) {
    while (this.isConnectionInProgress) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    try {
      const values = logEntries.map(log => {
        const timestamp = log.timestamp instanceof Date ? log.timestamp : new Date(log.timestamp);
        return `(
        ${this.sequelize.escape(log.hostname)},
        ${this.sequelize.escape(log.pid)},
        ${this.sequelize.escape(log.source)},
        ${this.sequelize.escape(timestamp.toISOString().slice(0, 19).replace('T', ' '))},
        ${this.sequelize.escape(log.level)},
        ${this.sequelize.escape(log.message)},
        ${this.sequelize.escape(log.meta)}
      )`;
      }).join(',');

      const sql = `
      INSERT INTO errsole_logs (hostname, pid, source, timestamp, level, message, meta)
      VALUES ${values};
    `;

      await this.sequelize.query(sql, { logging: false });
    } catch (err) { }
    return {};
  }

  /**
   * Retrieves log entries from the database based on specified filters.
   *
   * @async
   * @function getLogs
   * @param {LogFilter} [filters] - Filters to apply for log retrieval.
   * @returns {Promise<{items: Log[]}>} - A Promise that resolves with an object containing log items.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getLogs (filters = {}) {
    // Set default limit if not provided
    const defaultLimit = 100;
    filters.limit = filters.limit || defaultLimit;

    const where = {};
    let sortOrder = [['id', 'DESC']];
    let shouldReverse = true;

    // Apply filters
    if (filters.hostname) where.hostname = filters.hostname;
    if (filters.pid) where.pid = filters.pid;
    if (filters.sources) where.source = { [Sequelize.Op.in]: filters.sources };
    if (filters.levels) where.level = { [Sequelize.Op.in]: filters.levels };
    if (filters.level_json) {
      where[Sequelize.Op.or] = filters.level_json.map(levelObj => ({
        [Sequelize.Op.and]: [{ source: levelObj.source }, { level: levelObj.level }]
      }));
    }
    if (filters.lt_id) {
      where.id = { [Sequelize.Op.lt]: filters.lt_id };
      sortOrder = [['id', 'DESC']];
      shouldReverse = true;
    } else if (filters.gt_id) {
      where.id = { [Sequelize.Op.gt]: filters.gt_id };
      sortOrder = [['id', 'ASC']];
      shouldReverse = false;
    } else if (filters.lte_timestamp || filters.gte_timestamp) {
      where.timestamp = {};
      if (filters.lte_timestamp) {
        where.timestamp[Sequelize.Op.lte] = new Date(filters.lte_timestamp);
        sortOrder = [['timestamp', 'DESC']];
        shouldReverse = true;
      }
      if (filters.gte_timestamp) {
        where.timestamp[Sequelize.Op.gte] = new Date(filters.gte_timestamp);
        sortOrder = [['timestamp', 'ASC']];
        shouldReverse = false;
      }
    }

    const result = await this.errsoleLogs.findAll({
      where,
      order: sortOrder,
      limit: filters.limit,
      attributes: { exclude: ['meta'] },
      raw: true
    });

    if (shouldReverse) result.reverse();

    return { items: result };
  }

  /**
   * Retrieves log entries from the database based on specified search terms and filters.
   *
   * @async
   * @function searchLogs
   * @param {string[]} searchTerms - An array of search terms.
   * @param {LogFilter} [filters] - Filters to refine the search.
   * @returns {Promise<{items: Log[]}>} - A promise that resolves with an object containing an array of log items.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async searchLogs (searchTerms, filters = {}) {
    filters.limit = filters.limit || 100;
    let gteTimestamp, lteTimestamp;
    if (filters.gte_timestamp && !filters.lte_timestamp) {
      filters.gte_timestamp = new Date(filters.gte_timestamp);
      lteTimestamp = new Date(filters.gte_timestamp.getTime() + 24 * 60 * 60 * 1000);
    }
    if (filters.lte_timestamp && !filters.gte_timestamp) {
      filters.lte_timestamp = new Date(filters.lte_timestamp);
      gteTimestamp = new Date(filters.lte_timestamp.getTime() - 24 * 60 * 60 * 1000);
    }

    const where = {
      message: {
        [Sequelize.Op.and]: searchTerms.map(searchTerm => ({
          [Sequelize.Op.like]: `%${searchTerm}%`
        }))
      }
    };
    let sortOrder = [['id', 'DESC']];
    let shouldReverse = true;

    // Apply filters
    if (filters.hostname) {
      where.hostname = filters.hostname;
    }
    if (filters.pid) {
      where.pid = filters.pid;
    }
    if (filters.sources) {
      where.source = { [Sequelize.Op.in]: filters.sources };
    }
    if (filters.levels) {
      where.level = { [Sequelize.Op.in]: filters.levels };
    }
    if (filters.level_json) {
      where[Sequelize.Op.or] = filters.level_json.map(levelObj => ({
        [Sequelize.Op.and]: [{ source: levelObj.source }, { level: levelObj.level }]
      }));
    }
    if (filters.lt_id) {
      where.id = { [Sequelize.Op.lt]: filters.lt_id };
      sortOrder = [['id', 'DESC']];
      shouldReverse = true;
    }
    if (filters.gt_id) {
      where.id = { [Sequelize.Op.gt]: filters.gt_id };
      sortOrder = [['id', 'ASC']];
      shouldReverse = false;
    }
    if (filters.lte_timestamp || filters.gte_timestamp) {
      where.timestamp = {};
      if (filters.lte_timestamp) {
        where.timestamp[Sequelize.Op.lte] = new Date(filters.lte_timestamp);
        sortOrder = [['id', 'DESC']];
        shouldReverse = true;
      }
      if (filters.gte_timestamp) {
        where.timestamp[Sequelize.Op.gte] = new Date(filters.gte_timestamp);
        sortOrder = [['id', 'ASC']];
        shouldReverse = false;
      }
      if (lteTimestamp) {
        where.timestamp[Sequelize.Op.lte] = new Date(lteTimestamp);
        filters.lte_timestamp = lteTimestamp;
      }
      if (gteTimestamp) {
        where.timestamp[Sequelize.Op.gte] = new Date(gteTimestamp);
        filters.gte_timestamp = gteTimestamp;
      }
    }

    const result = await this.errsoleLogs.findAll({
      where,
      order: sortOrder,
      limit: filters.limit,
      attributes: { exclude: ['meta'] },
      raw: true
    });

    if (shouldReverse) result.reverse();

    return { items: result, filters };
  }

  /**
   * Retrieves the meta data of a log entry.
   *
   * @async
   * @function getMeta
   * @param {number} id - The unique ID of the log entry.
   * @returns {Promise<{item: meta, id}>}  - A Promise that resolves with an object containing the log ID and its associated metadata.
   * @throws {Error} - Throws an error if the log entry is not found or the operation fails.
   */
  async getMeta (id) {
    const result = await this.errsoleLogs.findOne({
      where: { id },
      attributes: ['id', 'meta'],
      raw: true
    });

    if (!result) {
      throw new Error('Log entry not found.');
    }

    return { item: { id: result.id, meta: result.meta } };
  }

  /**
   * Ensures that the Time To Live (TTL) configuration for logs is set.
   *
   * @async
   * @function ensureLogsTTL
   * @returns {Promise<{}>} - A promise that resolves with an empty object once the TTL configuration is confirmed or updated.
   */
  async ensureLogsTTL () {
    const DEFAULT_TTL = 2592000000; // 30 days in milliseconds
    try {
      const configResult = await this.getConfig('logsTTL');
      if (!configResult.item) {
        await this.setConfig('logsTTL', DEFAULT_TTL.toString());
      }
      this.deleteExpiredLogs();
    } catch (err) {
      console.error(err);
    }
    return {};
  }

  /**
   * Deletes expired logs based on TTL configuration.
   *
   * @async
   * @function deleteExpiredLogs
   */
  async deleteExpiredLogs () {
    try {
      const configResult = await this.getConfig('logsTTL');
      if (!configResult.item) {
        throw new Error('Could not find the TTL configuration for logs.');
      }

      const logsTTL = parseInt(configResult.item.value, 10);
      const expirationTime = new Date(new Date().getTime() - logsTTL);

      while (true) {
        const deletedRowCount = await this.errsoleLogs.destroy({
          where: {
            timestamp: {
              [Sequelize.Op.lt]: expirationTime
            }
          },
          limit: 1000
        });
        const delayTime = deletedRowCount ? 1000 : 3600000; // 1 second if rows were deleted, otherwise 1 hour
        await this.delay(delayTime);
      }
    } catch (err) {
      console.error(err);
    }
  }

  async delay (ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Creates a new user record in the database.
   *
   * @async
   * @function createUser
   * @param {Object} user - The user data.
   * @param {string} user.name - The name of the user.
   * @param {string} user.email - The email address of the user.
   * @param {string} user.password - The password of the user.
   * @param {string} user.role - The role of the user.
   * @returns {Promise<{item: User}>} - A promise that resolves with an object containing the new user item.
   * @throws {Error} - Throws an error if the user creation fails due to duplicate email or other database issues.
   */
  async createUser (user) {
    const SALT_ROUNDS = 10;
    try {
      const hashedPassword = await bcrypt.hash(user.password, SALT_ROUNDS);
      const result = await this.errsoleUsers.create({
        name: user.name,
        email: user.email,
        hashedPassword,
        role: user.role
      });
      const userItem = result.dataValues;
      delete userItem.hashedPassword;
      return { item: userItem };
    } catch (err) {
      if (err.name === 'SequelizeUniqueConstraintError') throw new Error('A user with the provided email already exists.');
      throw err;
    }
  }

  /**
   * Verifies a user's credentials against stored records.
   *
   * @async
   * @function verifyUser
   * @param {string} email - The email address of the user.
   * @param {string} password - The password of the user
   * @returns {Promise<{item: User}>} - A promise that resolves with an object containing the user item upon successful verification.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async verifyUser (email, password) {
    if (!email || !password) throw new Error('Both email and password are required for verification.');

    const user = await this.errsoleUsers.findOne({
      where: { email },
      raw: true
    });
    if (!user) throw new Error('User not found.');

    const isPasswordCorrect = await bcrypt.compare(password, user.hashedPassword);
    if (!isPasswordCorrect) throw new Error('Incorrect password.');

    // Exclude password before returning the user object
    delete user.hashedPassword;
    return { item: user };
  }

  /**
   * Retrieves the total count of users from the database.
   *
   * @async
   * @function getUserCount
   * @returns {Promise<{count: number}>} - A promise that resolves with an object containing the count of users.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getUserCount () {
    const count = await this.errsoleUsers.count();
    return { count };
  }

  /**
   * Retrieves all user records from the database.
   *
   * @async
   * @function getAllUsers
   * @returns {Promise<{items: User[]}>} - A promise that resolves with an object containing an array of user items.
   * @throws {Error} - Throws an error if the operation fails.
   */
  async getAllUsers () {
    const users = await this.errsoleUsers.findAll({
      attributes: { exclude: ['hashedPassword'] },
      raw: true
    });
    return { items: users };
  }

  /**
   * Retrieves a user record from the database based on the provided email.
   *
   * @async
   * @function getUserByEmail
   * @param {string} email - The email address of the user.
   * @returns {Promise<{item: User}>} - A Promise that resolves with an object containing the user item.
   * @throws {Error} - Throws an error if no user matches the email address.
   */
  async getUserByEmail (email) {
    if (!email) throw new Error('Email is required.');

    const user = await this.errsoleUsers.findOne({
      where: { email },
      attributes: { exclude: ['hashedPassword'] },
      raw: true
    });
    if (!user) throw new Error('User not found.');

    return { item: user };
  }

  /**
   * Updates a user's record in the database based on the provided email.
   *
   * @async
   * @function updateUserByEmail
   * @param {string} email - The email address of the user to be updated.
   * @param {Object} updates - The updates to be applied to the user record.
   * @returns {Promise<{item: User}>} - A Promise that resolves with an object containing the updated user item.
   * @throws {Error} - Throws an error if no updates could be applied or the user is not found.
   */
  async updateUserByEmail (email, updates) {
    // Validate input parameters
    if (!email) throw new Error('Email is required.');
    if (!updates || Object.keys(updates).length === 0) throw new Error('No updates provided.');

    // Prevent updates to restricted fields
    const restrictedFields = ['id', 'hashedPassword'];
    restrictedFields.forEach(field => delete updates[field]);

    const user = await this.errsoleUsers.findOne({ where: { email } });
    if (!user) throw new Error('User not found.');

    // Apply the updates
    const [updateCount] = await this.errsoleUsers.update(updates, { where: { email } });
    if (updateCount === 0) throw new Error('No updates applied.');

    // Retrieve the updated user information
    const updatedUser = await this.errsoleUsers.findOne({
      where: { email },
      attributes: { exclude: ['hashedPassword'] },
      raw: true
    });
    if (!updatedUser) throw new Error('Failed to retrieve updated user details.');

    return { item: updatedUser };
  }

  /**
   * Updates a user's password in the database.
   *
   * @async
   * @function updatePassword
   * @param {string} email - The email address of the user whose password is to be updated.
   * @param {string} currentPassword - The current password of the user for verification.
   * @param {string} newPassword - The new password to replace the current one.
   * @returns {Promise<{item: User}>} - A Promise that resolves with an object containing the updated user item (excluding sensitive information).
   * @throws {Error} - If the user is not found, if the current password is incorrect, or if the password update fails.
   */
  async updatePassword (email, currentPassword, newPassword) {
    if (!email || !currentPassword || !newPassword) throw new Error('Email, current password, and new password are required.');

    const user = await this.errsoleUsers.findOne({ where: { email }, raw: true });
    if (!user) throw new Error('User not found.');

    const isPasswordCorrect = await bcrypt.compare(currentPassword, user.hashedPassword);
    if (!isPasswordCorrect) throw new Error('Current password is incorrect.');

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const [updateCount] = await this.errsoleUsers.update({ hashedPassword }, {
      where: { email }
    });
    if (updateCount === 0) {
      throw new Error('Password update failed.');
    }

    delete user.hashedPassword;
    return { item: user };
  }

  /**
   * Deletes a user record from the database.
   *
   * @async
   * @function deleteUser
   * @param {number} id - The unique ID of the user to be deleted.
   * @returns {Promise<{}>} - A Promise that resolves with an empty object upon successful deletion of the user.
   * @throws {Error} - Throws an error if no user is found with the given ID or if the database operation fails.
   */
  async deleteUser (userId) {
    if (!userId) throw new Error('User ID is required.');

    const user = await this.errsoleUsers.findOne({ where: { id: userId } });
    if (!user) throw new Error('User not found.');

    await user.destroy();

    return { item: {} };
  }

  async getBufferSize () {
    const dialect = this.errsoleLogs.sequelize.getDialect();

    if (dialect === 'mysql') {
      const [results] = await this.errsoleLogs.sequelize.query("SHOW VARIABLES LIKE 'sort_buffer_size';");
      return parseInt(results[0].Value, 10);
    }

    if (dialect === 'postgres') {
      const [results] = await this.errsoleLogs.sequelize.query('SHOW work_mem;');
      const size = results[0].work_mem;
      return this.convertToBytes(size);
    }

    if (dialect === 'sqlite') {
      const [cacheSizeResult] = await this.errsoleLogs.sequelize.query('PRAGMA cache_size;');
      const [tempStoreResult] = await this.errsoleLogs.sequelize.query('PRAGMA temp_store;');
      return {
        cache_size: parseInt(cacheSizeResult[0].cache_size, 10),
        temp_store: tempStoreResult[0].temp_store
      };
    }
  }

  convertToBytes (size) {
    const units = {
      kB: 1024,
      MB: 1024 * 1024,
      GB: 1024 * 1024 * 1024
    };

    const unit = size.replace(/[0-9\s]/g, '');
    const value = parseInt(size.replace(/[a-zA-Z\s]/g, ''), 10);

    return value * (units[unit] || 1);
  }

  async setBufferSizes () {
    const desiredSize = 8 * 1024 * 1024;
    const dialect = this.errsoleLogs.sequelize.getDialect();
    const currentSize = await this.getBufferSize();

    if (dialect === 'mysql' && currentSize < desiredSize) {
      await this.errsoleLogs.sequelize.query('SET SESSION sort_buffer_size = 8388608;');
    }

    if (dialect === 'postgres' && currentSize < desiredSize) {
      await this.errsoleLogs.sequelize.query("SET LOCAL work_mem = '8MB';");
    }

    if (dialect === 'sqlite') {
      if (currentSize.cache_size < 10000) {
        await this.errsoleLogs.sequelize.query('PRAGMA cache_size = 10000;');
      }
      if (currentSize.temp_store !== 'MEMORY') {
        await this.errsoleLogs.sequelize.query('PRAGMA temp_store = MEMORY;');
      }
    }
  }
}

module.exports = ErrsoleSequelize;
