import React, { createContext, useContext, useEffect, useState } from 'react';
import { 
  type User as FirebaseUser, 
  onAuthStateChanged,
  signInWithEmailAndPassword,
  signOut as firebaseSignOut,
  sendPasswordResetEmail,
  GoogleAuthProvider,
  signInWithPopup
} from 'firebase/auth';
import { auth } from '../lib/firebase/config';
import { aiClient } from '../lib/api/aiService';
import type { UserProfile, UserRole } from '../types';

interface AuthContextType {
  user: FirebaseUser | null;
  profile: UserProfile | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  logout: () => Promise<void>;
  resetPassword: (email: string) => Promise<void>;
  isDemo: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isDemo, setIsDemo] = useState<boolean>(false);

  // Sync profile details via backend API
  const syncProfile = async (firebaseUser: FirebaseUser) => {
    try {
      const res = await aiClient.get(`/users/${firebaseUser.uid}`);
      if (res.data) {
        setProfile({
          id: res.data.id || firebaseUser.uid,
          email: res.data.email || firebaseUser.email || '',
          displayName: res.data.displayName || firebaseUser.displayName || firebaseUser.email?.split('@')[0] || 'User',
          avatarUrl: res.data.avatarUrl || firebaseUser.photoURL || undefined,
          role: (res.data.role as UserRole) || 'user',
          createdAt: res.data.createdAt || new Date().toISOString(),
          updatedAt: res.data.updatedAt || new Date().toISOString(),
        });
        return;
      }
    } catch (err: any) {
      // If 404, user doesn't exist yet — create them
      if (err?.response?.status === 404) {
        try {
          const defaultRole: UserRole = firebaseUser.email === 'admin@cyberneura.ai' ? 'admin' : 'user';
          await aiClient.post('/users', {
            email: firebaseUser.email || '',
            role: defaultRole,
            id: firebaseUser.uid,
          });
        } catch (createErr) {
          console.warn('Could not create user profile via backend:', createErr);
        }
      } else {
        console.warn('Could not sync user profile from backend:', err);
      }
    }

    // Fallback profile
    setProfile({
      id: firebaseUser.uid,
      email: firebaseUser.email || '',
      displayName: firebaseUser.displayName || firebaseUser.email?.split('@')[0] || 'User',
      role: firebaseUser.email === 'admin@cyberneura.ai' ? 'admin' : 'user',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  };

  useEffect(() => {
    // Check if Firebase is using dummy keys or missing API configuration
    const isFirebaseConfigured = import.meta.env.VITE_FIREBASE_API_KEY && !import.meta.env.VITE_FIREBASE_API_KEY.includes('mock');
    
    if (!isFirebaseConfigured) {
      // Running in Demo mode: load last profile or fallback
      console.log('Firebase credentials are mock/not-configured. Running in Demo Mode.');
      setIsDemo(true);
      const savedUser = localStorage.getItem('cyberneura_demo_user');
      if (savedUser) {
        const u = JSON.parse(savedUser);
        setUser(u.firebase);
        setProfile(u.profile);
      }
      setLoading(false);
      return;
    }

    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        setUser(firebaseUser);
        await syncProfile(firebaseUser);
      } else {
        setUser(null);
        setProfile(null);
      }
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  const login = async (email: string, password: string) => {
    if (isDemo) {
      // Simulate successful demo login with artificial latency
      await new Promise(resolve => setTimeout(resolve, 800));
      
      const mockFirebaseUser = {
        uid: 'demo-uid-12345',
        email,
        displayName: email.split('@')[0],
        emailVerified: true,
        photoURL: null,
        getIdToken: async () => 'mock-id-token-jwt'
      } as unknown as FirebaseUser;
      
      const mockProfile: UserProfile = {
        id: 'demo-uid-12345',
        email,
        displayName: email.split('@')[0],
        role: email === 'admin@cyberneura.ai' ? 'admin' : 'user',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      setUser(mockFirebaseUser);
      setProfile(mockProfile);
      localStorage.setItem('cyberneura_demo_user', JSON.stringify({
        firebase: mockFirebaseUser,
        profile: mockProfile
      }));
      return;
    }

    await signInWithEmailAndPassword(auth, email, password);
  };

  const loginWithGoogle = async () => {
    if (isDemo) {
      await login('google-user@cyberneura.ai', 'demo-password');
      return;
    }
    const provider = new GoogleAuthProvider();
    await signInWithPopup(auth, provider);
  };

  const logout = async () => {
    if (isDemo) {
      setUser(null);
      setProfile(null);
      localStorage.removeItem('cyberneura_demo_user');
      return;
    }
    await firebaseSignOut(auth);
  };

  const resetPassword = async (email: string) => {
    if (isDemo) {
      await new Promise(resolve => setTimeout(resolve, 500));
      console.log(`Demo password reset request submitted for: ${email}`);
      return;
    }
    await sendPasswordResetEmail(auth, email);
  };

  return (
    <AuthContext.Provider value={{ user, profile, loading, login, loginWithGoogle, logout, resetPassword, isDemo }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
