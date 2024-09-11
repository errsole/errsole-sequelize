const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const { Sequelize, DataTypes, Op } = require('sequelize');
const ErrsoleSequelize = require('../lib/index');
/* globals expect, jest, beforeEach, it, afterEach, describe */

jest.mock('bcryptjs', () => ({
  hash: jest.fn(),
  compare: jest.fn()
}));

jest.mock('sequelize', () => {
  const mSequelize = {
    define: jest.fn(),
    sync: jest.fn(),
    authenticate: jest.fn(),
    getQueryInterface: jest.fn().mockReturnValue({
      removeIndex: jest.fn(),
      addIndex: jest.fn()
    }),
    findAll: jest.fn(),
    bulkCreate: jest.fn(),
    findOne: jest.fn(),
    upsert: jest.fn(),
    update: jest.fn(),
    count: jest.fn(),
    destroy: jest.fn()
  };
  return {
    Sequelize: jest.fn(() => mSequelize),
    DataTypes: {
      BIGINT: jest.fn(),
      STRING: jest.fn(),
      INTEGER: jest.fn(),
      DATE: jest.fn(),
      NOW: jest.fn(),
      TEXT: jest.fn()
    },
    Op: {
      in: 'in',
      or: 'or',
      and: 'and',
      lt: 'lt',
      gt: 'gt',
      lte: 'lte',
      gte: 'gte'
    }
  };
});

describe('ErrsoleSequelize', () => {
  let errsoleSequelize;
  let sequelizeInstance;
  let cronJob;

  beforeEach(async () => {
    sequelizeInstance = new Sequelize();
    errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

    // Mock setInterval and cron.schedule
    jest.useFakeTimers();
    jest.spyOn(global, 'setInterval');
    cronJob = { stop: jest.fn() };
    jest.spyOn(cron, 'schedule').mockReturnValue(cronJob);

    // Suppress console.error
    jest.spyOn(console, 'error').mockImplementation(() => {});

    // Mock ensureLogsTTL and emit
    jest.spyOn(errsoleSequelize, 'ensureLogsTTL').mockResolvedValue();
    jest.spyOn(errsoleSequelize, 'emit').mockImplementation(() => {});
    jest.spyOn(errsoleSequelize, 'deleteExpiredLogs').mockResolvedValue();

    // Mock defineModels to ensure models are set up
    await errsoleSequelize.defineModels();

    // Mock the errsoleConfig model's methods
    errsoleSequelize.errsoleConfig = {
      findOne: jest.fn(),
      upsert: jest.fn()
    };

    // Mock the errsoleLogs model's methods
    errsoleSequelize.errsoleLogs = {
      findAll: jest.fn(),
      bulkCreate: jest.fn()
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
    console.error.mockRestore();
  });

  describe('#constructor', () => {
    it('should initialize Sequelize instance and define models', async () => {
      expect(sequelizeInstance.define).toHaveBeenCalled();
      await errsoleSequelize.syncModels();
      expect(sequelizeInstance.sync).toHaveBeenCalled();
    });
  });

  describe('#defineModels', () => {
    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });
    });

    it('should define ErrsoleLogs model correctly', async () => {
      await errsoleSequelize.defineModels();
      expect(sequelizeInstance.define).toHaveBeenCalledWith(
        'ErrsoleLogs',
        {
          id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
          hostname: DataTypes.STRING,
          pid: DataTypes.INTEGER,
          source: DataTypes.STRING,
          timestamp: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
          level: { type: DataTypes.STRING, allowNull: false, defaultValue: 'info' },
          message: DataTypes.TEXT,
          meta: DataTypes.TEXT,
          errsole_id: { type: DataTypes.BIGINT, allowNull: true }
        },
        {
          tableName: 'errsole_logs_v2',
          timestamps: false,
          indexes: [
            { fields: ['source', 'level', 'id'] },
            { fields: ['source', 'level', 'timestamp'] },
            { fields: ['hostname', 'pid', 'id'] },
            { fields: ['errsole_id'] }

          ]
        }
      );
    });

    it('should define ErrsoleUsers model correctly', async () => {
      await errsoleSequelize.defineModels();
      expect(sequelizeInstance.define).toHaveBeenCalledWith(
        'ErrsoleUsers',
        {
          id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
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
          role: { type: DataTypes.STRING, allowNull: false }
        },
        {
          tableName: 'errsole_users',
          timestamps: false
        }
      );
    });

    it('should define ErrsoleConfig model correctly', async () => {
      await errsoleSequelize.defineModels();
      expect(sequelizeInstance.define).toHaveBeenCalledWith(
        'ErrsoleConfig',
        {
          id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
          key: { type: DataTypes.STRING, unique: true, allowNull: false },
          value: { type: DataTypes.STRING, allowNull: false }
        },
        {
          tableName: 'errsole_config',
          freezeTableName: true,
          timestamps: false
        }
      );
    });
  });

  describe('#getConfig', () => {
    it('should retrieve a configuration based on the provided key', async () => {
      const config = { key: 'testKey', value: 'testValue' };
      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce({ dataValues: config });

      const result = await errsoleSequelize.getConfig('testKey');

      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'testKey' } });
      expect(result).toEqual({ item: config });
    });

    it('should return an empty object if configuration key is not found', async () => {
      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce(null);

      const result = await errsoleSequelize.getConfig('nonexistentKey');

      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'nonexistentKey' } });
      expect(result).toEqual({});
    });

    it('should handle errors during the query execution', async () => {
      const error = new Error('Query error');
      errsoleSequelize.errsoleConfig.findOne.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.getConfig('testKey')).rejects.toThrow('Query error');
      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'testKey' } });
    });
  });

  describe('#setConfig', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleConfig model's methods
      errsoleSequelize.errsoleConfig = {
        upsert: jest.fn(),
        findOne: jest.fn()
      };
    });

    it('should insert a new configuration if it does not exist', async () => {
      const config = { key: 'newKey', value: 'newValue' };
      errsoleSequelize.errsoleConfig.upsert.mockResolvedValueOnce([config, true]);
      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce({ dataValues: config });

      const result = await errsoleSequelize.setConfig('newKey', 'newValue');

      expect(errsoleSequelize.errsoleConfig.upsert).toHaveBeenCalledWith({ key: 'newKey', value: 'newValue' });
      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'newKey' } });
      expect(result).toEqual({ item: config });
    });

    it('should update an existing configuration', async () => {
      const config = { key: 'existingKey', value: 'updatedValue' };
      errsoleSequelize.errsoleConfig.upsert.mockResolvedValueOnce([config, false]);
      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce({ dataValues: config });

      const result = await errsoleSequelize.setConfig('existingKey', 'updatedValue');

      expect(errsoleSequelize.errsoleConfig.upsert).toHaveBeenCalledWith({ key: 'existingKey', value: 'updatedValue' });
      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'existingKey' } });
      expect(result).toEqual({ item: config });
    });

    it('should return an empty object if the configuration key is not found after upsert', async () => {
      errsoleSequelize.errsoleConfig.upsert.mockResolvedValueOnce([null, true]);
      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce(null);

      const result = await errsoleSequelize.setConfig('nonexistentKey', 'value');

      expect(errsoleSequelize.errsoleConfig.upsert).toHaveBeenCalledWith({ key: 'nonexistentKey', value: 'value' });
      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'nonexistentKey' } });
      expect(result).toEqual({});
    });

    it('should handle errors during the upsert operation', async () => {
      const error = new Error('Upsert error');
      errsoleSequelize.errsoleConfig.upsert.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.setConfig('key', 'value')).rejects.toThrow('Upsert error');
      expect(errsoleSequelize.errsoleConfig.upsert).toHaveBeenCalledWith({ key: 'key', value: 'value' });
    });

    it('should handle errors during the findOne operation', async () => {
      const error = new Error('FindOne error');
      errsoleSequelize.errsoleConfig.upsert.mockResolvedValueOnce([{ key: 'key', value: 'value' }, true]);
      errsoleSequelize.errsoleConfig.findOne.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.setConfig('key', 'value')).rejects.toThrow('FindOne error');
      expect(errsoleSequelize.errsoleConfig.upsert).toHaveBeenCalledWith({ key: 'key', value: 'value' });
      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'key' } });
    });
  });

  describe('#deleteConfig', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleConfig model's methods
      errsoleSequelize.errsoleConfig = {
        findOne: jest.fn()
      };
    });

    it('should delete configuration by key', async () => {
      const config = {
        key: 'testKey',
        destroy: jest.fn()
      };

      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce(config);

      const result = await errsoleSequelize.deleteConfig('testKey');

      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'testKey' } });
      expect(config.destroy).toHaveBeenCalled();
      expect(result).toEqual({});
    });

    it('should throw an error if the configuration key is not found', async () => {
      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce(null);

      await expect(errsoleSequelize.deleteConfig('nonexistentKey')).rejects.toThrow('Configuration not found.');

      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'nonexistentKey' } });
    });

    it('should handle errors during the findOne operation', async () => {
      const error = new Error('FindOne error');
      errsoleSequelize.errsoleConfig.findOne.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.deleteConfig('testKey')).rejects.toThrow('FindOne error');

      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'testKey' } });
    });

    it('should handle errors during the destroy operation', async () => {
      const config = {
        key: 'testKey',
        destroy: jest.fn().mockRejectedValueOnce(new Error('Destroy error'))
      };

      errsoleSequelize.errsoleConfig.findOne.mockResolvedValueOnce(config);

      await expect(errsoleSequelize.deleteConfig('testKey')).rejects.toThrow('Destroy error');

      expect(errsoleSequelize.errsoleConfig.findOne).toHaveBeenCalledWith({ where: { key: 'testKey' } });
      expect(config.destroy).toHaveBeenCalled();
    });
  });

  describe('#postLogs', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleLogs model's bulkCreate method
      errsoleSequelize.errsoleLogs = {
        bulkCreate: jest.fn()
      };
    });

    it('should wait if isConnectionInProgress is true', async () => {
      errsoleSequelize.isConnectionInProgress = true;

      const logEntries = [{ message: 'test log' }];
      const setTimeoutSpy = jest.spyOn(global, 'setTimeout').mockImplementation((cb) => cb());

      const promise = errsoleSequelize.postLogs(logEntries);

      // Simulate changing isConnectionInProgress to false
      setTimeout(() => {
        errsoleSequelize.isConnectionInProgress = false;
      }, 50);

      await promise;

      expect(setTimeoutSpy).toHaveBeenCalled();
      setTimeoutSpy.mockRestore();
    });

    it('should call bulkCreate with log entries', async () => {
      const logEntries = [{ message: 'test log' }];

      errsoleSequelize.isConnectionInProgress = false;
      await errsoleSequelize.postLogs(logEntries);

      expect(errsoleSequelize.errsoleLogs.bulkCreate).toHaveBeenCalledWith(logEntries, { logging: false });
    });

    it('should return an empty object', async () => {
      const logEntries = [{ message: 'test log' }];

      errsoleSequelize.isConnectionInProgress = false;
      const result = await errsoleSequelize.postLogs(logEntries);

      expect(result).toEqual({});
    });

    it('should handle errors during bulkCreate', async () => {
      const logEntries = [{ message: 'test log' }];
      errsoleSequelize.errsoleLogs.bulkCreate.mockRejectedValueOnce(new Error('bulkCreate error'));

      errsoleSequelize.isConnectionInProgress = false;
      const result = await errsoleSequelize.postLogs(logEntries);

      expect(result).toEqual({});
      expect(errsoleSequelize.errsoleLogs.bulkCreate).toHaveBeenCalledWith(logEntries, { logging: false });
    });
  });

  describe('#getLogs', () => {
    it('should set default limit if not provided', async () => {
      const logs = [{ id: 1, message: 'test log' }];
      errsoleSequelize.errsoleLogs.findAll.mockResolvedValueOnce(logs);

      const result = await errsoleSequelize.getLogs();

      expect(errsoleSequelize.errsoleLogs.findAll).toHaveBeenCalledWith(expect.objectContaining({ limit: 100 }));
      expect(result).toEqual({ items: logs });
    });

    it('should apply hostname filter', async () => {
      const logs = [{ id: 1, hostname: 'localhost', message: 'test log' }];
      errsoleSequelize.errsoleLogs.findAll.mockResolvedValueOnce(logs);

      const result = await errsoleSequelize.getLogs({ hostname: 'localhost' });

      expect(errsoleSequelize.errsoleLogs.findAll).toHaveBeenCalledWith(expect.objectContaining({
        where: { hostname: 'localhost' }
      }));
      expect(result).toEqual({ items: logs });
    });

    it('should apply pid filter', async () => {
      const logs = [{ id: 1, pid: 1234, message: 'test log' }];
      errsoleSequelize.errsoleLogs.findAll.mockResolvedValueOnce(logs);

      const result = await errsoleSequelize.getLogs({ pid: 1234 });

      expect(errsoleSequelize.errsoleLogs.findAll).toHaveBeenCalledWith(expect.objectContaining({
        where: { pid: 1234 }
      }));
      expect(result).toEqual({ items: logs });
    });

    it('should handle default behavior without filters', async () => {
      const logs = [{ id: 1, message: 'test log' }];
      errsoleSequelize.errsoleLogs.findAll.mockResolvedValueOnce(logs);

      const result = await errsoleSequelize.getLogs();

      expect(errsoleSequelize.errsoleLogs.findAll).toHaveBeenCalledWith(expect.objectContaining({
        where: {},
        order: [['id', 'DESC']],
        limit: 100,
        attributes: { exclude: ['meta'] },
        raw: true
      }));
      expect(result).toEqual({ items: logs });
    });

    it('should handle errors during the query execution', async () => {
      const error = new Error('Query error');
      errsoleSequelize.errsoleLogs.findAll.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.getLogs()).rejects.toThrow('Query error');
      expect(errsoleSequelize.errsoleLogs.findAll).toHaveBeenCalledWith(expect.objectContaining({
        where: {},
        order: [['id', 'DESC']],
        limit: 100,
        attributes: { exclude: ['meta'] },
        raw: true
      }));
    });
  });

  describe('#getMeta', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleLogs model's findOne method
      errsoleSequelize.errsoleLogs = {
        findOne: jest.fn()
      };
    });

    it('should retrieve the meta data for a given log entry', async () => {
      const logEntry = { id: 1, meta: '{"some": "data"}' };
      errsoleSequelize.errsoleLogs.findOne.mockResolvedValueOnce(logEntry);

      const result = await errsoleSequelize.getMeta(1);

      expect(errsoleSequelize.errsoleLogs.findOne).toHaveBeenCalledWith({
        where: { id: 1 },
        attributes: ['id', 'meta'],
        raw: true
      });
      expect(result).toEqual({ item: { id: logEntry.id, meta: logEntry.meta } });
    });

    it('should throw an error if the log entry is not found', async () => {
      errsoleSequelize.errsoleLogs.findOne.mockResolvedValueOnce(null);

      await expect(errsoleSequelize.getMeta(999)).rejects.toThrow('Log entry not found.');

      expect(errsoleSequelize.errsoleLogs.findOne).toHaveBeenCalledWith({
        where: { id: 999 },
        attributes: ['id', 'meta'],
        raw: true
      });
    });

    it('should handle errors during the database query execution', async () => {
      const error = new Error('Query error');
      errsoleSequelize.errsoleLogs.findOne.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.getMeta(1)).rejects.toThrow('Query error');

      expect(errsoleSequelize.errsoleLogs.findOne).toHaveBeenCalledWith({
        where: { id: 1 },
        attributes: ['id', 'meta'],
        raw: true
      });
    });
  });

  describe('#ensureLogsTTL', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the getConfig and setConfig methods
      errsoleSequelize.getConfig = jest.fn();
      errsoleSequelize.setConfig = jest.fn();
    });

    afterEach(() => {
      jest.clearAllMocks();
      jest.useRealTimers();
    });

    it('should set the default TTL if no configuration is found', async () => {
      errsoleSequelize.getConfig.mockResolvedValueOnce({});

      await errsoleSequelize.ensureLogsTTL();

      expect(errsoleSequelize.getConfig).toHaveBeenCalledWith('logsTTL');
      expect(errsoleSequelize.setConfig).toHaveBeenCalledWith('logsTTL', '2592000000');
    });

    it('should not set the default TTL if the configuration already exists', async () => {
      const config = { item: { key: 'logsTTL', value: '2592000000' } };
      errsoleSequelize.getConfig.mockResolvedValueOnce(config);

      await errsoleSequelize.ensureLogsTTL();

      expect(errsoleSequelize.getConfig).toHaveBeenCalledWith('logsTTL');
      expect(errsoleSequelize.setConfig).not.toHaveBeenCalled();
    });

    it('should handle errors during the configuration retrieval or setting process', async () => {
      const error = new Error('Config error');
      errsoleSequelize.getConfig.mockRejectedValueOnce(error);
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

      await errsoleSequelize.ensureLogsTTL();

      expect(errsoleSequelize.getConfig).toHaveBeenCalledWith('logsTTL');
      expect(errsoleSequelize.setConfig).not.toHaveBeenCalled();
      expect(consoleErrorSpy).toHaveBeenCalledWith(error);

      consoleErrorSpy.mockReset(); // Reset the mock instead of mockRestore
    });
  });

  describe('#deleteExpiredLogs', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the getConfig and errsoleLogs methods
      errsoleSequelize.getConfig = jest.fn();
      errsoleSequelize.errsoleLogs = {
        destroy: jest.fn()
      };

      // Mock the delay method
      jest.spyOn(errsoleSequelize, 'delay').mockResolvedValue();
    });

    afterEach(() => {
      jest.clearAllMocks();
      jest.useRealTimers();
    });

    it('should set deleteExpiredLogsRunning to true during execution and false afterwards', async () => {
      errsoleSequelize.getConfig.mockResolvedValueOnce({});
      errsoleSequelize.errsoleLogs.destroy.mockResolvedValueOnce(0);

      await errsoleSequelize.deleteExpiredLogs();

      expect(errsoleSequelize.deleteExpiredLogsRunning).toBe(false);
    });

    it('should set deleteExpiredLogsRunning to false if an error occurs', async () => {
      const error = new Error('Deletion error');

      errsoleSequelize.getConfig.mockResolvedValueOnce({});
      errsoleSequelize.errsoleLogs.destroy.mockRejectedValueOnce(error);

      await errsoleSequelize.deleteExpiredLogs();

      expect(errsoleSequelize.deleteExpiredLogsRunning).toBe(false);
    });
  });

  describe('#createUser', () => {
    let errsoleSequelize;
    let bcrypt;
    let user;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });
      bcrypt = require('bcryptjs');

      // Mock the errsoleUsers model's create method
      errsoleSequelize.errsoleUsers = {
        create: jest.fn()
      };

      // Sample user data
      user = {
        name: 'John Doe',
        email: 'john.doe@example.com',
        password: 'password123',
        role: 'admin'
      };
    });

    it('should hash the user password and create a new user', async () => {
      const hashedPassword = 'hashed_password';
      bcrypt.hash.mockResolvedValueOnce(hashedPassword);
      const createdUser = { ...user, id: 1, hashedPassword };
      delete createdUser.password;
      errsoleSequelize.errsoleUsers.create.mockResolvedValueOnce({ dataValues: createdUser });

      const result = await errsoleSequelize.createUser(user);

      expect(bcrypt.hash).toHaveBeenCalledWith(user.password, 10);
      expect(errsoleSequelize.errsoleUsers.create).toHaveBeenCalledWith({
        name: user.name,
        email: user.email,
        hashedPassword,
        role: user.role
      });
      expect(result).toEqual({ item: { id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' } });
    });

    it('should throw an error if a user with the provided email already exists', async () => {
      const error = new Error('SequelizeUniqueConstraintError');
      error.name = 'SequelizeUniqueConstraintError';
      bcrypt.hash.mockResolvedValueOnce('hashed_password');
      errsoleSequelize.errsoleUsers.create.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.createUser(user)).rejects.toThrow('A user with the provided email already exists.');

      expect(bcrypt.hash).toHaveBeenCalledWith(user.password, 10);
      expect(errsoleSequelize.errsoleUsers.create).toHaveBeenCalledWith({
        name: user.name,
        email: user.email,
        hashedPassword: 'hashed_password',
        role: user.role
      });
    });

    it('should throw the original error for other Sequelize errors', async () => {
      const error = new Error('Database error');
      bcrypt.hash.mockResolvedValueOnce('hashed_password');
      errsoleSequelize.errsoleUsers.create.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.createUser(user)).rejects.toThrow('Database error');

      expect(bcrypt.hash).toHaveBeenCalledWith(user.password, 10);
      expect(errsoleSequelize.errsoleUsers.create).toHaveBeenCalledWith({
        name: user.name,
        email: user.email,
        hashedPassword: 'hashed_password',
        role: user.role
      });
    });

    it('should not include the hashed password in the returned user object', async () => {
      const hashedPassword = 'hashed_password';
      bcrypt.hash.mockResolvedValueOnce(hashedPassword);
      const createdUser = { ...user, id: 1, hashedPassword };
      delete createdUser.password;
      errsoleSequelize.errsoleUsers.create.mockResolvedValueOnce({ dataValues: createdUser });

      const result = await errsoleSequelize.createUser(user);

      expect(result.item).not.toHaveProperty('hashedPassword');
      expect(result).toEqual({ item: { id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' } });
    });
  });

  describe('#verifyUser', () => {
    let errsoleSequelize;
    let bcrypt;
    let user;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });
      bcrypt = require('bcryptjs');

      // Mock the errsoleUsers model's findOne method
      errsoleSequelize.errsoleUsers = {
        findOne: jest.fn()
      };

      // Sample user data
      user = {
        id: 1,
        name: 'John Doe',
        email: 'john.doe@example.com',
        hashedPassword: 'hashed_password',
        role: 'admin'
      };
    });

    it('should throw an error if email or password is not provided', async () => {
      await expect(errsoleSequelize.verifyUser(null, 'password123')).rejects.toThrow('Both email and password are required for verification.');
      await expect(errsoleSequelize.verifyUser('john.doe@example.com', null)).rejects.toThrow('Both email and password are required for verification.');
    });

    it('should throw an error if the user is not found', async () => {
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(null);

      await expect(errsoleSequelize.verifyUser('john.doe@example.com', 'password123')).rejects.toThrow('User not found.');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { email: 'john.doe@example.com' }, raw: true });
    });

    it('should throw an error if the password is incorrect', async () => {
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);
      bcrypt.compare.mockResolvedValueOnce(false);

      await expect(errsoleSequelize.verifyUser('john.doe@example.com', 'wrongpassword')).rejects.toThrow('Incorrect password.');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { email: 'john.doe@example.com' }, raw: true });
      expect(bcrypt.compare).toHaveBeenCalledWith('wrongpassword', user.hashedPassword);
    });

    it('should verify the user successfully and return the user object without the hashed password', async () => {
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);
      bcrypt.compare.mockResolvedValueOnce(true);

      const result = await errsoleSequelize.verifyUser('john.doe@example.com', 'password123');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { email: 'john.doe@example.com' }, raw: true });
      expect(bcrypt.compare).toHaveBeenCalledWith('password123', 'hashed_password');
      expect(result).toEqual({ item: { id: user.id, name: user.name, email: user.email, role: user.role } });
    });
  });

  describe('#getUserCount', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleUsers model's count method
      errsoleSequelize.errsoleUsers = {
        count: jest.fn()
      };
    });

    it('should return the correct user count', async () => {
      errsoleSequelize.errsoleUsers.count.mockResolvedValueOnce(10);

      const result = await errsoleSequelize.getUserCount();

      expect(errsoleSequelize.errsoleUsers.count).toHaveBeenCalled();
      expect(result).toEqual({ count: 10 });
    });

    it('should handle errors during the count query', async () => {
      const error = new Error('Query error');
      errsoleSequelize.errsoleUsers.count.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.getUserCount()).rejects.toThrow('Query error');
      expect(errsoleSequelize.errsoleUsers.count).toHaveBeenCalled();
    });
  });

  describe('#getAllUsers', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleUsers model's findAll method
      errsoleSequelize.errsoleUsers = {
        findAll: jest.fn()
      };
    });

    it('should return all users excluding hashedPassword', async () => {
      const users = [
        { id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' },
        { id: 2, name: 'Jane Smith', email: 'jane.smith@example.com', role: 'user' }
      ];
      errsoleSequelize.errsoleUsers.findAll.mockResolvedValueOnce(users);

      const result = await errsoleSequelize.getAllUsers();

      expect(errsoleSequelize.errsoleUsers.findAll).toHaveBeenCalledWith({
        attributes: { exclude: ['hashedPassword'] },
        raw: true
      });
      expect(result).toEqual({ items: users });
    });

    it('should handle errors during the query execution', async () => {
      const error = new Error('Query error');
      errsoleSequelize.errsoleUsers.findAll.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.getAllUsers()).rejects.toThrow('Query error');
      expect(errsoleSequelize.errsoleUsers.findAll).toHaveBeenCalledWith({
        attributes: { exclude: ['hashedPassword'] },
        raw: true
      });
    });
  });

  describe('#getUserByEmail', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleUsers model's findOne method
      errsoleSequelize.errsoleUsers = {
        findOne: jest.fn()
      };
    });

    it('should throw an error if email is not provided', async () => {
      await expect(errsoleSequelize.getUserByEmail()).rejects.toThrow('Email is required.');
    });

    it('should return the user object excluding hashedPassword if user is found', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' };
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);

      const result = await errsoleSequelize.getUserByEmail('john.doe@example.com');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({
        where: { email: 'john.doe@example.com' },
        attributes: { exclude: ['hashedPassword'] },
        raw: true
      });
      expect(result).toEqual({ item: user });
    });

    it('should throw an error if user is not found', async () => {
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(null);

      await expect(errsoleSequelize.getUserByEmail('nonexistent@example.com')).rejects.toThrow('User not found.');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({
        where: { email: 'nonexistent@example.com' },
        attributes: { exclude: ['hashedPassword'] },
        raw: true
      });
    });

    it('should handle errors during the query execution', async () => {
      const error = new Error('Query error');
      errsoleSequelize.errsoleUsers.findOne.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.getUserByEmail('john.doe@example.com')).rejects.toThrow('Query error');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({
        where: { email: 'john.doe@example.com' },
        attributes: { exclude: ['hashedPassword'] },
        raw: true
      });
    });
  });

  describe('#updateUserByEmail', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleUsers model's methods
      errsoleSequelize.errsoleUsers = {
        findOne: jest.fn(),
        update: jest.fn()
      };
    });

    it('should throw an error if email is not provided', async () => {
      await expect(errsoleSequelize.updateUserByEmail()).rejects.toThrow('Email is required.');
    });

    it('should throw an error if no updates are provided', async () => {
      await expect(errsoleSequelize.updateUserByEmail('john.doe@example.com', {})).rejects.toThrow('No updates provided.');
    });

    it('should throw an error if user is not found', async () => {
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(null);

      await expect(errsoleSequelize.updateUserByEmail('nonexistent@example.com', { name: 'John Doe' })).rejects.toThrow('User not found.');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { email: 'nonexistent@example.com' } });
    });

    it('should apply the updates and return the updated user information', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' };
      const updatedUser = { id: 1, name: 'Jane Doe', email: 'john.doe@example.com', role: 'admin' };
      errsoleSequelize.errsoleUsers.findOne
        .mockResolvedValueOnce(user) // Initial find
        .mockResolvedValueOnce(updatedUser); // Find after update
      errsoleSequelize.errsoleUsers.update.mockResolvedValueOnce([1]);

      const result = await errsoleSequelize.updateUserByEmail('john.doe@example.com', { name: 'Jane Doe' });

      expect(errsoleSequelize.errsoleUsers.update).toHaveBeenCalledWith(
        { name: 'Jane Doe' },
        { where: { email: 'john.doe@example.com' } }
      );
      expect(result).toEqual({ item: updatedUser });
    });

    it('should throw an error if no updates are applied', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' };
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);
      errsoleSequelize.errsoleUsers.update.mockResolvedValueOnce([0]);

      await expect(errsoleSequelize.updateUserByEmail('john.doe@example.com', { name: 'Jane Doe' })).rejects.toThrow('No updates applied.');

      expect(errsoleSequelize.errsoleUsers.update).toHaveBeenCalledWith(
        { name: 'Jane Doe' },
        { where: { email: 'john.doe@example.com' } }
      );
    });

    it('should throw an error if failed to retrieve updated user details', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' };
      errsoleSequelize.errsoleUsers.findOne
        .mockResolvedValueOnce(user) // Initial find
        .mockResolvedValueOnce(null); // Find after update
      errsoleSequelize.errsoleUsers.update.mockResolvedValueOnce([1]);

      await expect(errsoleSequelize.updateUserByEmail('john.doe@example.com', { name: 'Jane Doe' })).rejects.toThrow('Failed to retrieve updated user details.');

      expect(errsoleSequelize.errsoleUsers.update).toHaveBeenCalledWith(
        { name: 'Jane Doe' },
        { where: { email: 'john.doe@example.com' } }
      );
    });

    it('should handle errors during the update process', async () => {
      const error = new Error('Update error');
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce({ id: 1, name: 'John Doe', email: 'john.doe@example.com', role: 'admin' });
      errsoleSequelize.errsoleUsers.update.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.updateUserByEmail('john.doe@example.com', { name: 'Jane Doe' })).rejects.toThrow('Update error');

      expect(errsoleSequelize.errsoleUsers.update).toHaveBeenCalledWith(
        { name: 'Jane Doe' },
        { where: { email: 'john.doe@example.com' } }
      );
    });
  });

  describe('#updatePassword', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleUsers model's methods
      errsoleSequelize.errsoleUsers = {
        findOne: jest.fn(),
        update: jest.fn()
      };

      // Mock bcrypt methods
      bcrypt.compare = jest.fn();
      bcrypt.hash = jest.fn();
    });

    it('should throw an error if email, current password, or new password is not provided', async () => {
      await expect(errsoleSequelize.updatePassword()).rejects.toThrow('Email, current password, and new password are required.');
      await expect(errsoleSequelize.updatePassword('john.doe@example.com')).rejects.toThrow('Email, current password, and new password are required.');
      await expect(errsoleSequelize.updatePassword('john.doe@example.com', 'currentPassword')).rejects.toThrow('Email, current password, and new password are required.');
    });

    it('should throw an error if user is not found', async () => {
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(null);

      await expect(errsoleSequelize.updatePassword('nonexistent@example.com', 'currentPassword', 'newPassword')).rejects.toThrow('User not found.');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { email: 'nonexistent@example.com' }, raw: true });
    });

    it('should throw an error if current password is incorrect', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', hashedPassword: 'hashed_password' };
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);
      bcrypt.compare.mockResolvedValueOnce(false);

      await expect(errsoleSequelize.updatePassword('john.doe@example.com', 'wrongPassword', 'newPassword')).rejects.toThrow('Current password is incorrect.');

      expect(bcrypt.compare).toHaveBeenCalledWith('wrongPassword', 'hashed_password');
    });

    it('should update the password and return the user object without the hashed password', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', hashedPassword: 'hashed_password' };
      const newHashedPassword = 'new_hashed_password';

      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);
      bcrypt.compare.mockResolvedValueOnce(true);
      bcrypt.hash.mockResolvedValueOnce(newHashedPassword);
      errsoleSequelize.errsoleUsers.update.mockResolvedValueOnce([1]);

      const result = await errsoleSequelize.updatePassword('john.doe@example.com', 'currentPassword', 'newPassword');

      expect(bcrypt.compare).toHaveBeenCalledWith('currentPassword', 'hashed_password');
      expect(bcrypt.hash).toHaveBeenCalledWith('newPassword', 10);
      expect(errsoleSequelize.errsoleUsers.update).toHaveBeenCalledWith({ hashedPassword: newHashedPassword }, { where: { email: 'john.doe@example.com' } });
      expect(result).toEqual({ item: { id: user.id, name: user.name, email: user.email, role: user.role } });
    });

    it('should throw an error if password update fails', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', hashedPassword: 'hashed_password' };

      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);
      bcrypt.compare.mockResolvedValueOnce(true);
      bcrypt.hash.mockResolvedValueOnce('new_hashed_password');
      errsoleSequelize.errsoleUsers.update.mockResolvedValueOnce([0]);

      await expect(errsoleSequelize.updatePassword('john.doe@example.com', 'currentPassword', 'newPassword')).rejects.toThrow('Password update failed.');

      expect(errsoleSequelize.errsoleUsers.update).toHaveBeenCalledWith({ hashedPassword: 'new_hashed_password' }, { where: { email: 'john.doe@example.com' } });
    });

    it('should handle errors during the update process', async () => {
      const error = new Error('Update error');
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', hashedPassword: 'hashed_password' };

      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);
      bcrypt.compare.mockResolvedValueOnce(true);
      bcrypt.hash.mockResolvedValueOnce('new_hashed_password');
      errsoleSequelize.errsoleUsers.update.mockRejectedValueOnce(error);

      await expect(errsoleSequelize.updatePassword('john.doe@example.com', 'currentPassword', 'newPassword')).rejects.toThrow('Update error');

      expect(errsoleSequelize.errsoleUsers.update).toHaveBeenCalledWith({ hashedPassword: 'new_hashed_password' }, { where: { email: 'john.doe@example.com' } });
    });
  });

  describe('#deleteUser', () => {
    let errsoleSequelize;

    beforeEach(() => {
      errsoleSequelize = new ErrsoleSequelize({ dialect: 'sqlite', logging: false });

      // Mock the errsoleUsers model's methods
      errsoleSequelize.errsoleUsers = {
        findOne: jest.fn()
      };
    });

    it('should throw an error if userId is not provided', async () => {
      await expect(errsoleSequelize.deleteUser()).rejects.toThrow('User ID is required.');
    });

    it('should throw an error if the user is not found', async () => {
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(null);

      await expect(errsoleSequelize.deleteUser(999)).rejects.toThrow('User not found.');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { id: 999 } });
    });

    it('should delete the user and return an empty object', async () => {
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', destroy: jest.fn().mockResolvedValueOnce() };
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);

      const result = await errsoleSequelize.deleteUser(1);

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
      expect(user.destroy).toHaveBeenCalled();
      expect(result).toEqual({ item: {} });
    });

    it('should handle errors during the deletion process', async () => {
      const error = new Error('Deletion error');
      const user = { id: 1, name: 'John Doe', email: 'john.doe@example.com', destroy: jest.fn().mockRejectedValueOnce(error) };
      errsoleSequelize.errsoleUsers.findOne.mockResolvedValueOnce(user);

      await expect(errsoleSequelize.deleteUser(1)).rejects.toThrow('Deletion error');

      expect(errsoleSequelize.errsoleUsers.findOne).toHaveBeenCalledWith({ where: { id: 1 } });
      expect(user.destroy).toHaveBeenCalled();
    });
  });
});
