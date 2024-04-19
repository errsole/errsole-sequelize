/**
 * @typedef {Object} Log
 * @property {number | string} [id]
 * @property {string} [hostname]
 * @property {number} [pid]
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
 * @property {number | string} [lt_id]
 * @property {number | string} [gt_id]
 * @property {Date} [lte_timestamp]
 * @property {Date} [gte_timestamp]
 * @property {string[]} [levels]
 * @property {number} [limit=100]
 */

/**
 * @typedef {Object} Config
 * @property {number | string} id
 * @property {string} name
 * @property {string} value
 */

/**
 * @typedef {Object} User
 * @property {number | string} id
 * @property {string} name
 * @property {string} email
 * @property {string} role
 */

const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');

const saltRounds = 10;
const packageJSON = require('../package.json');

class ErrsoleSequelize {
  /**
   * Constructs an instance of the database handler using Sequelize.
   * This constructor initializes the Sequelize instance and sets up the database models and synchronization.
   * @param {Object} config - The configuration object for setting up the Sequelize connection.
   * @param {string} config.host - The hostname of the database server.
   * @param {string} config.username - The username for the database login.
   * @param {string} config.password - The password for the database login.
   * @param {string} config.database - The name of the database to connect to.
   * @param {string} config.dialect - The type of SQL dialect to be used (e.g., 'mysql', 'postgres', 'sqlite').
   */
  constructor ({ host, username, password, database, dialect, pool, storage }) {
    this.sequelize = new Sequelize(database, username, password, { host, dialect, storage, pool, logging: false });
    this.defineModels();
    this.syncModels();
    this.name = packageJSON.name;
    this.version = packageJSON.version || '0.0.0';
  }

  async defineModels () {
    this.errsoleLogs = this.sequelize.define('errsole_logs', {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true, allowNull: false },
      source: { type: DataTypes.STRING, allowNull: false },
      level: { type: DataTypes.STRING, allowNull: false },
      timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      hostname: DataTypes.STRING,
      pid: DataTypes.INTEGER,
      message: { type: DataTypes.TEXT, allowNull: false }
    }, {
      timestamps: false,
      indexes: [
        { fields: ['source', 'level', 'id'] },
        { fields: ['source', 'level', 'timestamp'] },
        { fields: ['hostname', 'pid', 'id'] },
        { type: 'FULLTEXT', fields: ['message'] }
      ]
    });

    this.errsoleUsers = this.sequelize.define('errsole_users', {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true, allowNull: false },
      name: DataTypes.STRING,
      email: { type: DataTypes.STRING, unique: true, allowNull: false, validate: { isEmail: true } },
      password: { type: DataTypes.STRING, allowNull: false, validate: { notEmpty: { msg: 'Password cannot be empty' } } },
      role: { type: DataTypes.STRING, allowNull: false }
    }, {
      timestamps: false
    });

    this.errsoleConfig = this.sequelize.define('errsole_config', {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      key: { type: DataTypes.STRING, unique: true },
      value: { type: DataTypes.STRING, allowNull: false }
    }, {
      tableName: 'errsole_config',
      freezeTableName: true,
      timestamps: false
    });
  }

  async syncModels () {
    await this.sequelize.authenticate();
    await this.sequelize.sync({ alter: true });
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
    const logs = Array.isArray(logEntries) ? logEntries : [logEntries];

    try {
      await this.errsoleLogs.bulkCreate(logs);
      return {};
    } catch (error) {
      return error.message;
    }
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

    // Construct the object based on filters
    const where = {};

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

    if (filters.gt_id) {
      where.id = { [Sequelize.Op.gt]: filters.gt_id };
    } else if (filters.lt_id) {
      where.id = { [Sequelize.Op.lt]: filters.lt_id };
    }

    if (filters.gte_timestamp || filters.lte_timestamp) {
      where.timestamp = {};
      if (filters.gte_timestamp) {
        where.timestamp[Sequelize.Op.gte] = new Date(filters.gte_timestamp);
      }
      if (filters.lte_timestamp) {
        where.timestamp[Sequelize.Op.lte] = new Date(filters.lte_timestamp);
      }
    }

    // Determine the sort order based on where parameters
    let sortOrder = [['timestamp', 'DESC']]; // Default sort order
    let shouldReverse = true;

    if (filters.gt_id) {
      sortOrder = [['id', 'ASC']];
      shouldReverse = false;
    } else if (filters.lt_id) {
      sortOrder = [['id', 'DESC']];
      shouldReverse = true;
    }

    const result = await this.errsoleLogs.findAll({
      where,
      order: sortOrder,
      limit: filters.limit
    });

    // Reverse the order of result if required
    if (shouldReverse) {
      result.reverse();
    }

    // Format result to match the expected output
    const formattedResult = result.map(doc => {
      const { id, ...rest } = doc.toJSON();
      return { id: id.toString(), ...rest };
    });

    return { items: formattedResult };
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
    const limit = filters.limit || 100;

    const where = {
      message: {
        [Sequelize.Op.and]: searchTerms.map(word => ({
          [Sequelize.Op.like]: `%${word}%`
        }))
      }
    };

    if (filters.hostname) {
      where.hostname = filters.hostname;
    }

    if (filters.pid) {
      where.pid = filters.pid;
    }

    if (filters.level) {
      where.level = filters.level;
    }

    if (filters.gte || filters.lte) {
      where.timestamp = {};
      if (filters.gte) {
        where.timestamp[Sequelize.Op.gte] = new Date(filters.gte);
      }
      if (filters.lte) {
        where.timestamp[Sequelize.Op.lte] = new Date(filters.lte);
      }
    }

    let order;
    if (filters.gt_id || filters.lt_id) {
      where.id = {};
      if (filters.gt_id) {
        where.id[Sequelize.Op.gt] = filters.gt_id;
        order = [['id', 'ASC']];
      }
      if (filters.lt_id) {
        where.id[Sequelize.Op.lt] = filters.lt_id;
        order = [['id', 'DESC']];
      }
    } else {
      order = [['timestamp', 'DESC']];
    }

    const result = await this.errsoleLogs.findAll({
      where,
      order,
      limit
    });

    if (filters.shouldReverse) {
      result.reverse();
    }

    // Format results to match the expected output
    const formattedResult = result.map(doc => {
      const { id, ...rest } = doc.toJSON();
      return { id: id.toString(), ...rest };
    });

    return { items: formattedResult };
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
    if (!user.email || !user.password) {
      throw new Error('User email and password required');
    }
    try {
      const hashedPassword = await bcrypt.hash(user.password, saltRounds);
      const result = await this.errsoleUsers.create({ name: user.name, email: user.email, password: hashedPassword, role: user.role });

      if (result.dataValues.email === user.email) {
        delete user.password;
        return { item: user };
      } else {
        throw new Error('User could not be created');
      }
    } catch (error) {
      if (error.name === 'SequelizeUniqueConstraintError') {
        throw new Error('Email already exists');
      } else {
        throw new Error(error.message);
      }
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
    if (!email || !password) {
      throw new Error('Email and password are required for verification');
    }
    const user = await this.errsoleUsers.findOne({ where: { email }, attributes: { exclude: password }, raw: true });
    if (!user) {
      throw new Error('Email not found');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new Error('Password does not match');
    }
    user.password = undefined;
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
      attributes: { exclude: ['password'] }
    });
    const transformedUsers = users.map(user => user.toJSON());
    return { items: transformedUsers };
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
    if (!result || !result.dataValues) {
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
    const result = await this.errsoleConfig.upsert({ key, value });
    if (result) {
      return { item: { id: result.id, key, value } };
    } else {
      throw new Error('Failed to update configuration');
    }
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
    if (!email) {
      throw new Error('Email is required');
    }
    const user = await this.errsoleUsers.findOne({ where: { email }, attributes: { exclude: ['password'] }, raw: true });

    if (!user) {
      throw new Error('User not found');
    } else {
      return { item: user };
    }
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
    if (!email) {
      throw new Error('Email is required');
    }
    if (!updates || Object.keys(updates).length === 0) {
      throw new Error('No updates provided');
    }
    delete updates.password;
    delete updates.id;
    const user = await this.errsoleUsers.findOne({ where: { email } });
    if (!user) {
      throw new Error('User not found');
    }
    const [updateCount] = await this.errsoleUsers.update(updates, {
      where: { email }
    });
    if (updateCount === 0) {
      throw new Error('No updates applied');
    }
    return { item: { email } };
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
    if (!email || !currentPassword || !newPassword) {
      throw new Error('Email, current password, and new password are required');
    }
    const user = await this.errsoleUsers.findOne({ where: { email } });
    if (!user) {
      throw new Error('User not found');
    }
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      throw new Error('Current password is incorrect');
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const [updateCount] = await this.errsoleUsers.update({ password: hashedPassword }, {
      where: { email }
    });

    if (updateCount === 0) {
      throw new Error('Password update failed');
    }

    return { item: { email } };
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
    if (!userId) {
      throw new Error('User ID is required');
    }
    const user = await this.errsoleUsers.findOne({ where: { id: userId } });
    if (!user) {
      throw new Error('User not found');
    }
    await user.destroy();
    return { item: {} };
  }
}

module.exports = ErrsoleSequelize;
