import { aiClient } from '../lib/api/aiService';
import { getFirebaseMessaging } from '../lib/firebase/config';
import type { Notification } from '../types';

export async function fetchNotifications(): Promise<Notification[]> {
  try {
    const res = await aiClient.get('/notifications');
    if (res.data && Array.isArray(res.data)) {
      return res.data;
    }
    return [];
  } catch {
    return [];
  }
}

export async function markNotificationAsRead(id: string): Promise<boolean> {
  try {
    await aiClient.post(`/notifications/${id}/read`);
    return true;
  } catch (err) {
    console.warn(`Could not mark notification ${id} as read:`, err);
    return false;
  }
}

export async function markAllNotificationsAsRead(): Promise<boolean> {
  try {
    await aiClient.post('/notifications/read-all');
    return true;
  } catch (err) {
    console.warn('Could not mark all notifications as read:', err);
    return false;
  }
}

export async function registerFCMToken(userId: string): Promise<string | null> {
  try {
    const messaging = await getFirebaseMessaging();
    if (!messaging) return null;

    const { getToken } = await import('firebase/messaging');
    const token = await getToken(messaging, {
      vapidKey: 'MOCK_VAPID_KEY_FOR_DEMO_PURPOSES_ONLY_PLACEHOLDER',
    });

    if (token) {
      console.log('FCM Registration token secured successfully.');
      return token;
    }
  } catch (err) {
    console.warn('FCM token registration failed:', err);
  }
  return null;
}
