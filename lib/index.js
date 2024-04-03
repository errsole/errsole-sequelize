const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcryptjs');

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
      const result = await this.errsoleLogs.bulkCreate(logs.map(log => ({
        level: log.level,
        message: log.message,
        timestamp: new Date()
      })));
      if (result.length > 0) {
        return { status: true, message: 'Logs posted successfully' };
      } else {
        return { status: false, message: 'Failed to post logs' };
      }
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async getLogs ({ level, gte, lte, limit = 50 }) {
    try {
      const where = {};
      if (level) where.level = level;
      if (gte || lte) {
        where.timestamp = {};
        if (gte) where.timestamp[Sequelize.Op.gte] = new Date(gte);
        if (lte) where.timestamp[Sequelize.Op.lte] = new Date(lte);
      }

      const logs = await this.errsoleLogs.findAll({
        where,
        order: [['timestamp', 'DESC']],
        limit
      });

      return logs.map(log => log.toJSON());
    } catch (err) {
      console.error('Error in getLogs:', err);
      throw err;
    }
  }

  async createUser (user) {
    if (!user.email || !user.password) {
      return { status: false, error: 'User email and password required' };
    }
    try {
      const wasCreated = await this.errsoleUsers.create({ name: user.name, email: user.email, password: user.password, role: user.role });

      if (wasCreated) {
        return { status: true, message: 'created' };
      } else {
        return { status: false, error: 'User could not be created' };
      }
    } catch (error) {
      if (error.name === 'SequelizeUniqueConstraintError') {
        return { status: false, error: 'Email already exists' };
      } else {
        return { status: false, error: error.message };
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
    const withoutpassword = {
      ...user,
      password: undefined
    };

    return withoutpassword;
  }

  async getNumberOfUsers () {
    const users = await this.errsoleUsers.count();
    return users;
  }

  async getAllUsers () {
    try {
      const users = await this.errsoleUsers.findAll({
        attributes: { exclude: ['password'] }
      });

      const transformedUsers = users.map(user => user.toJSON());

      return { status: true, data: transformedUsers };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async getConfig (name) {
    try {
      const configEntry = await this.errsoleConfigs.findOne({ where: { name } });
      return configEntry ? configEntry.value : null;
    } catch (error) {
      console.error('Error retrieving configuration:', error);
      throw error;
    }
  }

  async setConfig (name, value) {
    try {
      const wasCreated = await this.errsoleConfigs.upsert({ name, value });

      if (wasCreated) {
        return { status: true, message: 'created' };
      } else {
        return { status: false, error: 'No operation was performed' };
      }
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async getUserProfile (email) {
    if (!email) {
      return { status: false, error: 'Email is required' };
    }
    try {
      const user = await this.errsoleUsers.findOne({ where: { email }, attributes: { exclude: ['password'] }, raw: true });

      if (!user) {
        return { status: false, error: 'User not found' };
      } else {
        return { status: true, data: user };
      }
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async updateUserprofile (email, updates) {
    if (!email) {
      return { status: false, error: 'Email is required' };
    }
    if (!updates || Object.keys(updates).length === 0) {
      return { status: false, error: 'No updates provided' };
    }
    delete updates.password;
    delete updates.id;

    try {
      const [updatedCount] = await this.errsoleUsers.update(updates, { where: { email } });
      if (updatedCount === 0) {
        return { status: false, error: 'User not found or no updates applied' };
      }

      return { status: true, message: 'User profile updated successfully' };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async updatePassword (email, currentPassword, newPassword) {
    if (!email || !currentPassword || !newPassword) {
      return { status: false, error: 'Email, current password and new password are required' };
    }
    try {
      const user = await this.errsoleUsers.findOne({ where: { email } });
      if (!user) {
        return { status: false, error: 'User not found' };
      }
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return { status: false, error: 'Current password is incorrect' };
      }
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const [updateCount] = await this.errsoleUsers.update({ password: hashedPassword }, {
        where: { email }
      });

      if (updateCount === 0) {
        return { status: false, error: 'Password update failed' };
      }

      return { status: true, message: 'Password updated successfully' };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }

  async removeUser (userId) {
    if (!userId) {
      return { status: false, error: 'User ID is required' };
    }
    try {
      const user = await this.errsoleUsers.findOne({ where: { id: userId } });
      if (!user) {
        return { status: false, error: 'User not found' };
      }
      await user.destroy();
      return { status: true, message: 'User removed successfully' };
    } catch (error) {
      return { status: false, error: error.message };
    }
  }
}

module.exports = ErrsoleSequelize;
