import {
  pgTable,
  text,
  varchar,
  timestamp,
  jsonb,
  index,
  boolean,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table (required for Replit Auth)
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// User storage table (required for Replit Auth)
export const users = pgTable("users", {
  id: varchar("id").primaryKey().notNull(),
  email: varchar("email").unique(),
  firstName: varchar("first_name"),
  lastName: varchar("last_name"),
  profileImageUrl: varchar("profile_image_url"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export type UpsertUser = typeof users.$inferInsert;
export type User = typeof users.$inferSelect;

// Existing schema for the training platform
export const modules = pgTable("modules", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  slug: text("slug").notNull().unique(),
  description: text("description").notNull(),
  icon: text("icon").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const tasks = pgTable("tasks", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  moduleId: text("module_id").notNull(),
  status: text("status").notNull(),
  objective: text("objective").notNull(),
  toolsRequired: text("tools_required").array().notNull(),
  instructions: text("instructions").array().notNull(),
  commandExample: text("command_example"),
  commandOutput: text("command_output"),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const userProgress = pgTable("user_progress", {
  id: text("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  moduleId: text("module_id").notNull(),
  completedTasks: text("completed_tasks").array().notNull(),
  notes: text("notes"),
  lastAccessed: timestamp("last_accessed").defaultNow(),
});

export const tools = pgTable("tools", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  icon: text("icon").notNull(),
  description: text("description").notNull(),
  version: text("version").notNull(),
  type: text("type").notNull(),
  usageInstructions: text("usage_instructions").array().notNull(),
  imageUrl: text("image_url").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: text("id").primaryKey(),
  moduleId: text("module_id").notNull(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  endpoint: text("endpoint").notNull(),
  payload: text("payload").notNull(),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const insertUserSchema = createInsertSchema(users).pick({
  email: true,
  firstName: true,
  lastName: true,
  profileImageUrl: true,
});

export const insertModuleSchema = createInsertSchema(modules).pick({
  title: true,
  slug: true,
  description: true,
  icon: true,
});

export const insertTaskSchema = createInsertSchema(tasks).pick({
  title: true,
  moduleId: true,
  status: true,
  objective: true,
  toolsRequired: true,
  instructions: true,
  commandExample: true,
  commandOutput: true,
});

export const insertUserProgressSchema = createInsertSchema(userProgress).pick({
  userId: true,
  moduleId: true,
  completedTasks: true,
  notes: true,
});

export const insertToolSchema = createInsertSchema(tools).pick({
  name: true,
  icon: true,
  description: true,
  version: true,
  type: true,
  usageInstructions: true,
  imageUrl: true,
});

export const insertVulnerabilitySchema = createInsertSchema(vulnerabilities).pick({
  moduleId: true,
  name: true,
  description: true,
  endpoint: true,
  payload: true,
  isActive: true,
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type Module = typeof modules.$inferSelect;
export type InsertModule = z.infer<typeof insertModuleSchema>;
export type Task = typeof tasks.$inferSelect;
export type InsertTask = z.infer<typeof insertTaskSchema>;
export type UserProgress = typeof userProgress.$inferSelect;
export type InsertUserProgress = z.infer<typeof insertUserProgressSchema>;
export type Tool = typeof tools.$inferSelect;
export type InsertTool = z.infer<typeof insertToolSchema>;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type InsertVulnerability = z.infer<typeof insertVulnerabilitySchema>;