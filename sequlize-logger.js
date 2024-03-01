const Log = require('./SequlizeModule/LogModel');

async function SaveLog(level,logMessage){
    try {
        await Log.create({
          log: logMessage, 
          level: level,
        });
        console.log('Log saved:', { level, logMessage });
      } catch (error) {
        console.error('Error saving log:', error);
      }
}
async function saveInfoLog(log){
    return SaveLog('info',log);    
}

async function saveErrorLog(log){
    return SaveLog('error',log);
}

async function getLogs(level = '') {
    try {
      const whereClause = level ? { level } : {};
      return await Log.findAll({
        where: whereClause
      });
    } catch (error) {
      console.error('Error retrieving logs:', error);
      return [];
    }
  }
module.exports = {
    SaveLog,
    saveInfoLog,
    saveErrorLog,
    getLogs
}

