export type ModuleStatus = 'incomplete' | 'inprogress' | 'completed';

export type TaskStatus = 'incomplete' | 'inprogress' | 'completed';

export type DifficultyLevel = 'beginner' | 'intermediate' | 'advanced';

export interface Module {
  id: number;
  title: string;
  slug: string;
  description: string;
  icon: string;
  tasks: Task[];
  challenges?: Challenge[];
}

export interface Task {
  id: number;
  title: string;
  status: TaskStatus;
  objective: string;
  toolsRequired: string[];
  instructions: string[];
  commandExample: string;
  commandOutput: string;
  difficulty?: DifficultyLevel;
}

export interface Challenge {
  id: string;
  title: string;
  difficulty: DifficultyLevel;
  description: string;
  path: string;
  flag: string;
  points: number;
  category: string;
  hints?: string[];
}

export interface Tool {
  id: string;
  name: string;
  icon: string;
  description: string;
  version: string;
  type: string;
  usageInstructions: string[];
  imageUrl: string;
}

export interface UserProgress {
  userId: number;
  moduleId: number;
  completedTasks: number[];
  notes: string;
  lastAccessed: Date;
}

export interface LabEnvironment {
  status: 'running' | 'stopped' | 'error';
  targetUrl: string;
  targetIp: string;
}
