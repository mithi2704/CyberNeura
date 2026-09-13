import { aiClient } from '../lib/api/aiService';

export interface UserActivityRow {
  userId: string;
  email: string;
  scansToday: number;
  threatsBlocked: number;
  lastActive: string;
  status: 'online' | 'away' | 'offline';
  role: 'admin' | 'analyst' | 'viewer' | 'user';
}

export async function fetchUserActivities(): Promise<UserActivityRow[]> {
  try {
    const res = await aiClient.get('/users?page=1&page_size=50');
    if (res.data && Array.isArray(res.data.items)) {
      return res.data.items.map((u: any) => ({
        userId: u.userId || u.id?.slice(0, 5) || '---',
        email: u.email || 'operator@cyberneura.ai',
        scansToday: u.scansToday ?? 0,
        threatsBlocked: u.threatsBlocked ?? 0,
        lastActive: u.lastActive ?? 'Unknown',
        status: u.status ?? 'online',
        role: u.role ?? 'user',
      }));
    }
    return [];
  } catch (err) {
    console.warn('Backend /users unreachable:', err);
    return [];
  }
}

export async function createUserProfile(email: string, role: string, userId: string): Promise<boolean> {
  try {
    await aiClient.post('/users', { email, role, id: userId });
    return true;
  } catch (err) {
    console.warn('Backend user profile creation error:', err);
    return false;
  }
}

export async function deleteUserProfile(userId: string): Promise<boolean> {
  try {
    await aiClient.delete(`/users/${userId}`);
    return true;
  } catch (err) {
    console.warn('Backend delete user error:', err);
    return false;
  }
}
