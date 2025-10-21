import { Response, Request } from "express";
import { EncryptionService } from "./encryptionService";
import { TimeService } from "../timeService";
import * as crypto from "crypto";

const encryptionService = new EncryptionService();

// 改进的会话存储结构
interface SessionInfo {
  session_token: string;
  created_at: number;
  last_accessed: number;
  user_agent?: string;
  account_id?: string; // 可选的账号标识
  game_id?: string; // 游戏ID
  ip_address?: string; // 记录IP地址
  device_fingerprint?: string; // 设备指纹
}

const sessionStore: Map<string, SessionInfo> = new Map();
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24小时超时
const CLEANUP_INTERVAL = 5 * 60 * 1000; // 5分钟清理一次
const MAX_SESSIONS_BEFORE_CLEANUP = 1000; // 超过1000个会话时强制清理

const timeService = new TimeService();
let lastCleanupTime = Date.now();

// 启动后台清理任务
function startBackgroundCleanup() {
  setInterval(() => {
    const now = Date.now();
    if (now - lastCleanupTime > CLEANUP_INTERVAL) {
      smartCleanupExpiredSessions();
    }
  }, CLEANUP_INTERVAL);
}

// 启动后台清理
startBackgroundCleanup();

// 基于用户ID生成稳定的session_token
function generateStableSessionToken(userId: string): string {
  // 使用MD5哈希生成稳定的session_token
  const hash = crypto.createHash('md5').update(userId).digest('hex');
  // 格式化为UUID样式 (8-4-4-4-12)
  return `${hash.substring(0, 8)}-${hash.substring(8, 12)}-${hash.substring(12, 16)}-${hash.substring(16, 20)}-${hash.substring(20, 32)}`;
}

// 生成基于用户ID的会话键
function generateUserBasedSessionKey(userId: string): string {
  return `user_${userId}`;
}

// 智能清理过期会话的函数
function smartCleanupExpiredSessions() {
  const now = Date.now();
  
  // 检查是否需要清理
  const shouldCleanup = 
    (now - lastCleanupTime > CLEANUP_INTERVAL) || 
    (sessionStore.size > MAX_SESSIONS_BEFORE_CLEANUP);
  
  if (!shouldCleanup) {
    return; // 不需要清理，直接返回
  }
  
  console.log(`[Cleanup] Starting cleanup, current sessions: ${sessionStore.size}`);
  
  let cleanedCount = 0;
  const expiredKeys: string[] = [];
  
  // 先收集过期的键，避免在遍历时修改Map
  for (const [key, session] of sessionStore.entries()) {
    if (now - session.last_accessed > SESSION_TIMEOUT) {
      expiredKeys.push(key);
    }
  }
  
  // 批量删除过期的会话
  expiredKeys.forEach(key => {
    sessionStore.delete(key);
    cleanedCount++;
  });
  
  lastCleanupTime = now;
  
  if (cleanedCount > 0) {
    console.log(`[Cleanup] Cleaned up ${cleanedCount} expired sessions, remaining: ${sessionStore.size}`);
  }
}

// 轻量级清理检查（用于高频调用）
function quickCleanupCheck() {
  const now = Date.now();
  
  // 只在会话数量过多或时间间隔足够长时才清理
  if (sessionStore.size > MAX_SESSIONS_BEFORE_CLEANUP || 
      (now - lastCleanupTime > CLEANUP_INTERVAL)) {
    smartCleanupExpiredSessions();
  }
}

// 通过session_token直接查找会话
function findSessionByToken(sessionToken: string): { key: string; session: SessionInfo } | null {
  // 遍历所有会话，找到匹配的session_token
  for (const [key, session] of sessionStore.entries()) {
    if (session.session_token === sessionToken) {
      return { key, session };
    }
  }
  return null;
}

// 生成会话键（用于没有用户ID的情况）
function generateSessionKey(req: Request): string {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const userAgent = req.get('User-Agent') || 'unknown';
  const userAgentHash = Buffer.from(userAgent).toString('base64').slice(0, 8);
  return `device_${userAgentHash}`;
}

export function encryptAndSend(
  data: object,
  res: Response,
  req: Request,
  error_code: number = 0, //TODO create a error code ENUM from EAPI_jpn.gmd in GUI_msg.arc
  error_category: number = 0, //1 seems to retry automatically  2: error 3:would you like to retry question
  error_detail: string = "",
  status: number = 200,

) {
  // 轻量级清理检查（高频调用优化）
  quickCleanupCheck();
  
  const now = Date.now();
  const userId = req.body?.user_id || req.query?.user_id;
  const clientSessionToken = req.body?.session_id;
  
  // 调试信息
  console.log(`[Session Debug] User ID: ${userId}, Client Session: ${clientSessionToken}, IP: ${req.ip}`);
  
  let sessionInfo: SessionInfo;
  let sessionKey: string;
  
  // 如果有用户ID，直接生成基于用户ID的稳定session_token
  if (userId) {
    sessionKey = generateUserBasedSessionKey(userId);
    const session_token = generateStableSessionToken(userId);
    
    // 检查是否已存在该用户的会话
    const existingSession = sessionStore.get(sessionKey);
    
    if (existingSession && (now - existingSession.last_accessed <= SESSION_TIMEOUT)) {
      // 重用现有会话
      sessionInfo = existingSession;
      sessionInfo.last_accessed = now;
      sessionInfo.ip_address = req.ip || req.connection.remoteAddress || 'unknown';
      sessionStore.set(sessionKey, sessionInfo);
      console.log(`Reusing existing session for user ${userId}:`, sessionInfo.session_token);
    } else {
      // 创建新会话
      sessionInfo = {
        session_token,
        created_at: now,
        last_accessed: now,
        user_agent: req.get('User-Agent'),
        account_id: userId,
        game_id: req.body?.game_id,
        ip_address: req.ip || req.connection.remoteAddress || 'unknown',
        device_fingerprint: req.get('User-Agent') ? Buffer.from(req.get('User-Agent')!).toString('base64').slice(0, 8) : undefined
      };
      sessionStore.set(sessionKey, sessionInfo);
      console.log(`Generated stable session token for user ${userId}:`, session_token);
    }
  } else if (clientSessionToken) {
    // 如果有客户端提供的session_token，尝试查找现有会话
    const existingSession = findSessionByToken(clientSessionToken);
    
    if (existingSession && (now - existingSession.session.last_accessed <= SESSION_TIMEOUT)) {
      // 重用现有会话
      sessionKey = existingSession.key;
      sessionInfo = existingSession.session;
      sessionInfo.last_accessed = now;
      sessionInfo.ip_address = req.ip || req.connection.remoteAddress || 'unknown';
      sessionStore.set(sessionKey, sessionInfo);
      console.log(`Reusing existing session by token:`, sessionInfo.session_token);
    } else {
      // 创建新会话 - 使用客户端提供的session_token，但确保唯一性
      sessionKey = `client_${clientSessionToken}`;
      const session_token = clientSessionToken; // 使用客户端提供的token
      sessionInfo = {
        session_token,
        created_at: now,
        last_accessed: now,
        user_agent: req.get('User-Agent'),
        account_id: req.body?.user_id || req.query?.user_id,
        game_id: req.body?.game_id,
        ip_address: req.ip || req.connection.remoteAddress || 'unknown',
        device_fingerprint: req.get('User-Agent') ? Buffer.from(req.get('User-Agent')!).toString('base64').slice(0, 8) : undefined
      };
      sessionStore.set(sessionKey, sessionInfo);
      console.log(`Using client session token:`, session_token);
    }
  } else {
    // 没有用户ID和session_token，创建新会话
    sessionKey = generateSessionKey(req);
    const session_token = crypto.randomUUID().toString();
    sessionInfo = {
      session_token,
      created_at: now,
      last_accessed: now,
      user_agent: req.get('User-Agent'),
      account_id: req.body?.user_id || req.query?.user_id,
      game_id: req.body?.game_id,
      ip_address: req.ip || req.connection.remoteAddress || 'unknown',
      device_fingerprint: req.get('User-Agent') ? Buffer.from(req.get('User-Agent')!).toString('base64').slice(0, 8) : undefined
    };
    sessionStore.set(sessionKey, sessionInfo);
    console.log(`Generated new session token for ${sessionKey}:`, session_token);
  }
  
  const session_token = sessionInfo.session_token;

  const responseData = {
    ...data,
    error_code: error_code,
    error_category: error_category,
    error_detail: error_detail,
    app_ver_android: "09.03.06",
    app_ver_ios: "09.03.06",
    app_ver: "09.03.06",
    res_ver: 282, //controlls banner version url /download/android/v0282/stdDL/download.list Official Value: 282
    banner_ver: 91, //if set to 0 /api/banner/dllist/get is not called if you increment it to 1 it will be called then not called again untill incremented to 2 (Possible incremental update?) Official Value: 91
    session_id: session_token,
    block_seq: 0, //Possibly need to increment this for cycling encryption. (Client ignores if 0)
    one_day_time: timeService.getOneDayTime(),
    now_time: timeService.getNowTime(),
    relogin_time: timeService.getRelogTime(),
  };
  // console.log("Current Time Japan",timeService.getJapanTime())
  // console.log("Response: \n ############")
  // console.log(responseData)
  const encryptedData = encryptionService.encrypt(JSON.stringify(responseData));
  // console.log("now_time:",responseData.now_time)
  // console.log("relogin_time:",responseData.relogin_time)
  console.log("Response Body:\n", JSON.stringify(responseData, null, "\t"));

  res
    .status(status)
    .header("Content-Type", "application/octet-stream")
    .send(encryptedData);
}

export function decryptAndParse(data: Buffer) {
  const decryptedData = encryptionService.decrypt(data);
  const parsedData = JSON.parse(decryptedData);
  return parsedData;
}

// 新增的会话管理工具函数
export function getSessionInfo(sessionKey: string): SessionInfo | undefined {
  return sessionStore.get(sessionKey);
}

export function invalidateSession(sessionKey: string): boolean {
  return sessionStore.delete(sessionKey);
}

export function getAllActiveSessions(): Array<{key: string, info: SessionInfo}> {
  return Array.from(sessionStore.entries()).map(([key, info]) => ({key, info}));
}

export function getSessionCount(): number {
  return sessionStore.size;
}

// 强制清理所有会话（用于维护）
export function clearAllSessions(): void {
  sessionStore.clear();
  console.log("All sessions cleared");
}

// 根据用户标识查找会话（用于调试）
export function findSessionsByUser(identifier: string, type: 'account' | 'game' | 'session'): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const prefix = type === 'account' ? 'account_' : type === 'game' ? 'game_' : 'session_';
  const searchKey = `${prefix}${identifier}`;
  
  for (const [key, session] of sessionStore.entries()) {
    if (key === searchKey || 
        (type === 'account' && session.account_id === identifier) ||
        (type === 'game' && session.game_id === identifier)) {
      sessions.push(session);
    }
  }
  
  return sessions;
}

// 获取会话统计信息
export function getSessionStats(): {
  total: number;
  byType: { [key: string]: number };
  oldest: number;
  newest: number;
  lastCleanup: number;
  cleanupInterval: number;
} {
  const stats = {
    total: sessionStore.size,
    byType: {} as { [key: string]: number },
    oldest: Date.now(),
    newest: 0,
    lastCleanup: lastCleanupTime,
    cleanupInterval: CLEANUP_INTERVAL
  };
  
  for (const [key, session] of sessionStore.entries()) {
    const type = key.split('_')[0];
    stats.byType[type] = (stats.byType[type] || 0) + 1;
    stats.oldest = Math.min(stats.oldest, session.created_at);
    stats.newest = Math.max(stats.newest, session.created_at);
  }
  
  return stats;
}

// 获取性能统计信息
export function getPerformanceStats(): {
  sessionCount: number;
  lastCleanupTime: number;
  timeSinceLastCleanup: number;
  shouldCleanup: boolean;
} {
  const now = Date.now();
  return {
    sessionCount: sessionStore.size,
    lastCleanupTime: lastCleanupTime,
    timeSinceLastCleanup: now - lastCleanupTime,
    shouldCleanup: sessionStore.size > MAX_SESSIONS_BEFORE_CLEANUP || 
                   (now - lastCleanupTime > CLEANUP_INTERVAL)
  };
}

// 验证session_token是否基于用户ID生成
export function verifySessionToken(userId: string, sessionToken: string): boolean {
  const expectedToken = generateStableSessionToken(userId);
  return expectedToken === sessionToken;
}

// 根据用户ID获取预期的session_token
export function getExpectedSessionToken(userId: string): string {
  return generateStableSessionToken(userId);
}
