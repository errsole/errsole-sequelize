const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');
const saltRounds = 10;

class ErrsoleSequelize {
  constructor ({ host, username, password, database, dialect }) {
    this.sequelize = new Sequelize(database, username, password, { host, dialect, logging: false });
    this.defineModels();
    this.syncModels();
  }

  async defineModels () {
    this.errsoleLogs = this.sequelize.define('errsoleLog', {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      level: DataTypes.STRING,
      message: DataTypes.TEXT,
      timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
      public_ip: { type: DataTypes.STRING, allowNull: true },
      private_ip: { type: DataTypes.STRING, allowNull: true }
    }, {
      timestamps: false // disabling the createdAt and updatedAt columns while creating the models
    });

    this.errsoleUsers = this.sequelize.define('errsoleUser', {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      name: DataTypes.STRING,
      email: { type: DataTypes.STRING, unique: true, allowNull: false, validate: { isEmail: true } },
      password: { type: DataTypes.STRING, allowNull: false, validate: { notEmpty: { msg: 'Password cannot be empty' } } },
      role: DataTypes.STRING
    }, {
      timestamps: false // disabling the createdAt and updatedAt columns while creating the models
    });

    this.errsoleConfigs = this.sequelize.define('errsoleConfig', {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      name: { type: DataTypes.STRING, unique: true },
      value: DataTypes.STRING
    }, {
      timestamps: false // disabling the createdAt and updatedAt columns while creating the models
    });

    this.errsoleUsers.beforeCreate(async (user) => {
      user.password = await bcrypt.hash(user.password, 10);
    });
  }

  async syncModels () {
    await this.sequelize.authenticate();
    await this.sequelize.sync({ alter: true });
  }

  async postLogs (logEntries) {
    const logs = Array.isArray(logEntries) ? logEntries : [logEntries];

    try {
      await this.errsoleLogs.bulkCreate(logs.map(log => ({
        level: log.level,
        message: log.message,
        timestamp: new Date()
      })));
      return {};
    } catch (error) {
      return error.message;
    }
  }

  async getLogs (filters = {}) {
    filters.limit = filters.limit || 100;
    const where = {};
    if (filters.level) where.level = filters.level;
    if (filters.gte || filters.lte) {
      where.timestamp = {};
      if (filters.gte) where.timestamp[Sequelize.Op.gte] = new Date(filters.gte);
      if (filters.lte) where.timestamp[Sequelize.Op.lte] = new Date(filters.lte);
    }
    if (filters.gt_id || filters.lt_id) {
      where.id = {};
      if (filters.gt_id) where.id[Sequelize.Op.gt] = filters.gt_id;
      if (filters.lt_id) where.id[Sequelize.Op.lt] = filters.lt_id;
    }

    let order = [['timestamp', 'DESC']]; // Default sorting
    if (filters.gt_id) {
      order = [['id', 'ASC']];
    } else if (filters.lt_id || filters.lte) {
      order = [['id', 'DESC']];
    }

    const logs = await this.errsoleLogs.findAll({
      where,
      order,
      limit: filters.limit
    });

    // If sorting by `lt_id` or `lte`, reverse the array
    if (filters.lt_id || filters.lte) {
      logs.reverse();
    }

    return logs.map(log => log.toJSON());
  }

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

  async verifyUser ({ email, password }) {
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

  async getUserCount () {
    const count = await this.errsoleUsers.count();
    return { count };
  }

  async getAllUsers () {
    const users = await this.errsoleUsers.findAll({
      attributes: { exclude: ['password'] }
    });
    const transformedUsers = users.map(user => user.toJSON());
    return { items: transformedUsers };
  }

  async getConfig (name) {
    const configEntry = await this.errsoleConfigs.findOne({ where: { name } });
    const result = configEntry ? configEntry.value : null;
    return { item: result };
  }

  async setConfig (name, value) {
    const result = await this.errsoleConfigs.upsert({ name, value });
    if (result) {
      return { item: { id: result.id, name, value } };
    } else {
      throw new Error('Failed to update configuration');
    }
  }

  async getUserProfile (email) {
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

  async updateUserProfile (email, updates) {
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

  async removeUser (userId) {
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
