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
 * @property {string[]} [sources]
 * @property {number} [lt_id]
 * @property {number} [gt_id]
 * @property {Date} [lte_timestamp]
 * @property {Date} [gte_timestamp]
 * @property {string[]} [levels]
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
const saltRounds = 10;

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
      level: DataTypes.STRING,
      message: DataTypes.TEXT,
      meta: DataTypes.TEXT
    }, {
      tableName: 'errsole_logs',
      timestamps: false,
      indexes: [
        { fields: ['source', 'level', 'id'] },
        { fields: ['source', 'level', 'timestamp'] },
        { fields: ['hostname', 'pid', 'id'] },
        { type: 'FULLTEXT', fields: ['message'] }
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
    this.isConnectionInProgress = false;
    this.emit('ready');
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
    await this.errsoleLogs.bulkCreate(logEntries, { logging: false });
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
    // Set default limit if not provided
    const defaultLimit = 100;
    filters.limit = filters.limit || defaultLimit;

    const where = {
      message: {
        [Sequelize.Op.and]: searchTerms.map(word => ({
          [Sequelize.Op.like]: `%${word}%`
        }))
      }
    };
    let sortOrder = [['id', 'DESC']];
    let shouldReverse = true;

    // Apply filters
    if (filters.hostname) where.hostname = filters.hostname;
    if (filters.pid) where.pid = filters.pid;
    if (filters.sources) where.source = { [Sequelize.Op.in]: filters.sources };
    if (filters.levels) where.level = { [Sequelize.Op.in]: filters.levels };
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
      raw: true
    });

    if (shouldReverse) result.reverse();

    return { items: result };
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
    if (!result) {
      return {};
    }
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
    if (!result) {
      return {};
    }
    return { item: result.dataValues };
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
    try {
      const hashedPassword = await bcrypt.hash(user.password, saltRounds);
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
      where: { email },
      raw: true
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
   * @param {string} id - The unique ID of the user to be deleted.
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
}

module.exports = ErrsoleSequelize;
