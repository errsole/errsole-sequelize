declare module 'errsole-sequelize' {
    import { Options } from 'sequelize';
  
    interface Log {
      id?: number;
      hostname: string;
      pid: number;
      source: string;
      timestamp: Date;
      level: string;
      message: string;
      meta?: string;
      errsole_id?: number | null; 
    }
  
    interface Config {
      id: number;
      key: string;
      value: string;
    }
  
    interface User {
      id: number;
      name: string;
      email: string;
      role: string;
    }
  
    class ErrsoleSequelize {
      constructor(options: Options);
  
      getConfig(key: string): Promise<{ item: Config }>;
      setConfig(key: string, value: string): Promise<{ item: Config }>;
      deleteConfig(key: string): Promise<{}>;
  
      postLogs(logEntries: Log[]): Promise<{}>;
      getHostnames(): Promise<{ items: string[] }>;
      getLogs(filters?: any): Promise<{ items: Log[] }>;
      searchLogs(searchTerms: string[], filters?: any): Promise<{ items: Log[] }>;
  
      getMeta(id: number): Promise<{ item: { id: number; meta: string } }>;
  
      createUser(user: { name: string; email: string; password: string; role: string }): Promise<{ item: User }>;
      verifyUser(email: string, password: string): Promise<{ item: User }>;
      getUserCount(): Promise<{ count: number }>;
      getAllUsers(): Promise<{ items: User[] }>;
      getUserByEmail(email: string): Promise<{ item: User }>;
      updateUserByEmail(email: string, updates: Partial<User>): Promise<{ item: User }>;
      updatePassword(email: string, currentPassword: string, newPassword: string): Promise<{ item: User }>;
      deleteUser(userId: number): Promise<{}>;
    }
  
    export default ErrsoleSequelize;
  }
  