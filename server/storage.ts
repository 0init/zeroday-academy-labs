import {
  users, modules, tasks, userProgress, tools, vulnerabilities,
  type User, type InsertUser,
  type Module, type InsertModule,
  type Task, type InsertTask, 
  type UserProgress, type InsertUserProgress,
  type Tool, type InsertTool,
  type Vulnerability, type InsertVulnerability
} from "@shared/schema";

export interface IStorage {
  // User methods
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  
  // Module methods
  getModules(): Promise<Module[]>;
  getModuleById(id: string): Promise<Module | undefined>;
  getModuleBySlug(slug: string): Promise<Module | undefined>;
  createModule(module: InsertModule): Promise<Module>;
  
  // Task methods
  getTasksByModuleId(moduleId: string): Promise<Task[]>;
  createTask(task: InsertTask): Promise<Task>;
  updateTaskStatus(id: string, status: string): Promise<Task | undefined>;
  
  // Progress methods
  getUserProgress(userId: string, moduleId: string): Promise<UserProgress | undefined>;
  updateUserProgress(progress: InsertUserProgress): Promise<UserProgress>;
  
  // Tool methods
  getTools(): Promise<Tool[]>;
  getToolById(id: string): Promise<Tool | undefined>;
  createTool(tool: InsertTool): Promise<Tool>;
  
  // Vulnerability methods
  getVulnerabilities(): Promise<Vulnerability[]>;
  getVulnerabilityById(id: string): Promise<Vulnerability | undefined>;
  createVulnerability(vulnerability: InsertVulnerability): Promise<Vulnerability>;
  toggleVulnerability(id: string, isActive: boolean): Promise<Vulnerability | undefined>;
}

export class MemStorage implements IStorage {
  private usersMap: Map<string, User>;
  private modulesMap: Map<string, Module>;
  private tasksMap: Map<string, Task>;
  private userProgressMap: Map<string, UserProgress>; // key = userId_moduleId
  private toolsMap: Map<string, Tool>;
  private vulnerabilitiesMap: Map<string, Vulnerability>;
  
  private currentUserId: number;
  private currentModuleId: number;
  private currentTaskId: number;
  private currentToolId: number;
  private currentVulnerabilityId: number;

  constructor() {
    this.usersMap = new Map();
    this.modulesMap = new Map();
    this.tasksMap = new Map();
    this.userProgressMap = new Map();
    this.toolsMap = new Map();
    this.vulnerabilitiesMap = new Map();
    
    this.currentUserId = 1;
    this.currentModuleId = 1;
    this.currentTaskId = 1;
    this.currentToolId = 1;
    this.currentVulnerabilityId = 1;
    
    // Initialize with demo data
    this.initDemoData();
  }

  private initDemoData() {
    // Create demo modules
    const sqlInjectionModule: InsertModule = {
      title: 'SQL Injection',
      slug: 'sql-injection',
      description: 'Detecting and exploiting SQL injection vulnerabilities',
      icon: 'bug_report',
    };
    this.createModule(sqlInjectionModule);
    
    const brokenAuthModule: InsertModule = {
      title: 'Broken Authentication',
      slug: 'broken-authentication',
      description: 'Exploiting weak authentication mechanisms and session management',
      icon: 'lock_open',
    };
    this.createModule(brokenAuthModule);
    
    // Create demo tools
    const burpSuite: InsertTool = {
      name: 'Burp Suite',
      type: 'Web Application Security Testing',
      description: 'A comprehensive web application security testing platform.',
      icon: 'web_asset',
      version: '2023.10',
      usageInstructions: [
        'Configure browser proxy to route traffic through Burp',
        'Use Target tab to map application structure',
        'Intercept and modify requests in Proxy tab',
        'Perform automated scans in Scanner tab'
      ],
      imageUrl: 'https://portswigger.net/content/images/logos/burp-suite-pro-logo.svg',
    };
    this.createTool(burpSuite);
    
    const hydra: InsertTool = {
      name: 'Hydra',
      type: 'Brute Force Attack Tool',
      description: 'A parallelized login cracker which supports numerous protocols to attack.',
      icon: 'password',
      version: '9.3',
      usageInstructions: [
        'Identify target service and port',
        'Prepare username and password lists',
        'Configure protocol-specific attack options',
        'Monitor login attempt results'
      ],
      imageUrl: 'https://www.kali.org/tools/hydra/images/hydra-logo.svg',
    };
    this.createTool(hydra);
    
    // Create demo vulnerabilities
    const sqlVuln: InsertVulnerability = {
      moduleId: '1',
      name: 'SQL Injection',
      description: 'The application is vulnerable to SQL injection attacks through the login form.',
      endpoint: '/api/vuln/sqli',
      payload: "admin' OR '1'='1",
      isActive: true,
    };
    this.createVulnerability(sqlVuln);
  }

  async getUser(id: string): Promise<User | undefined> {
    return this.usersMap.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    for (const user of this.usersMap.values()) {
      if (user.email === username) {
        return user;
      }
    }
    return undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentUserId.toString();
    this.currentUserId++;
    const user: User = { 
      ...insertUser, 
      id,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.usersMap.set(id, user);
    return user;
  }

  async getModules(): Promise<Module[]> {
    return Array.from(this.modulesMap.values());
  }

  async getModuleById(id: string): Promise<Module | undefined> {
    return this.modulesMap.get(id);
  }

  async getModuleBySlug(slug: string): Promise<Module | undefined> {
    for (const module of this.modulesMap.values()) {
      if (module.slug === slug) {
        return module;
      }
    }
    return undefined;
  }

  async createModule(insertModule: InsertModule): Promise<Module> {
    const id = this.currentModuleId.toString();
    this.currentModuleId++;
    const module: Module = { 
      ...insertModule, 
      id,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.modulesMap.set(id, module);
    return module;
  }

  async getTasksByModuleId(moduleId: string): Promise<Task[]> {
    return Array.from(this.tasksMap.values()).filter(task => task.moduleId === moduleId);
  }

  async createTask(insertTask: InsertTask): Promise<Task> {
    const id = this.currentTaskId.toString();
    this.currentTaskId++;
    const task: Task = { 
      ...insertTask, 
      id,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.tasksMap.set(id, task);
    return task;
  }

  async updateTaskStatus(id: string, status: string): Promise<Task | undefined> {
    const task = this.tasksMap.get(id);
    if (!task) return undefined;

    const updatedTask: Task = { ...task, status, updatedAt: new Date() };
    this.tasksMap.set(id, updatedTask);
    return updatedTask;
  }

  async getUserProgress(userId: string, moduleId: string): Promise<UserProgress | undefined> {
    const key = `${userId}_${moduleId}`;
    return this.userProgressMap.get(key);
  }

  async updateUserProgress(insertProgress: InsertUserProgress): Promise<UserProgress> {
    const key = `${insertProgress.userId}_${insertProgress.moduleId}`;
    const existing = this.userProgressMap.get(key);
    
    if (existing) {
      const updatedProgress: UserProgress = {
        ...existing,
        ...insertProgress,
        lastAccessed: new Date()
      };
      this.userProgressMap.set(key, updatedProgress);
      return updatedProgress;
    } else {
      const id = `progress_${Date.now()}`;
      const newProgress: UserProgress = {
        id,
        ...insertProgress,
        lastAccessed: new Date()
      };
      this.userProgressMap.set(key, newProgress);
      return newProgress;
    }
  }

  async getTools(): Promise<Tool[]> {
    return Array.from(this.toolsMap.values());
  }

  async getToolById(id: string): Promise<Tool | undefined> {
    return this.toolsMap.get(id);
  }

  async createTool(insertTool: InsertTool): Promise<Tool> {
    const id = this.currentToolId.toString();
    this.currentToolId++;
    const tool: Tool = { 
      ...insertTool, 
      id,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.toolsMap.set(id, tool);
    return tool;
  }

  async getVulnerabilities(): Promise<Vulnerability[]> {
    return Array.from(this.vulnerabilitiesMap.values());
  }

  async getVulnerabilityById(id: string): Promise<Vulnerability | undefined> {
    return this.vulnerabilitiesMap.get(id);
  }

  async createVulnerability(insertVulnerability: InsertVulnerability): Promise<Vulnerability> {
    const id = this.currentVulnerabilityId.toString();
    this.currentVulnerabilityId++;
    const vulnerability: Vulnerability = { 
      ...insertVulnerability, 
      id,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    this.vulnerabilitiesMap.set(id, vulnerability);
    return vulnerability;
  }

  async toggleVulnerability(id: string, isActive: boolean): Promise<Vulnerability | undefined> {
    const vulnerability = this.vulnerabilitiesMap.get(id);
    if (!vulnerability) return undefined;

    const updatedVulnerability: Vulnerability = { 
      ...vulnerability, 
      isActive, 
      updatedAt: new Date() 
    };
    this.vulnerabilitiesMap.set(id, updatedVulnerability);
    return updatedVulnerability;
  }
}

export const storage = new MemStorage();