import React, { useState, useEffect } from 'react';
import { fetchUserActivities, createUserProfile, deleteUserProfile } from '../../services/userService';
import type { UserActivityRow } from '../../services/userService';
import { StatCard } from '../../components/ui/StatCard';
import { GlassCard } from '../../components/ui/GlassCard';
import { CyberButton } from '../../components/ui/CyberButton';
import { CyberInput } from '../../components/ui/CyberInput';
import { Users, AlertTriangle, Database, Trash2, UserPlus } from 'lucide-react';

export const UsersPage: React.FC = () => {
  const [users, setUsers] = useState<UserActivityRow[]>([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'admin' | 'analyst' | 'viewer' | 'user'>('user');
  const [loading, setLoading] = useState(false);

  const loadUsers = async () => {
    const list = await fetchUserActivities();
    setUsers(list);
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setLoading(true);
    
    // Simulate unique UUID
    const newUid = 'uid_' + Math.random().toString(36).substring(4);
    const success = await createUserProfile(email, role, newUid);
    
    if (success) {
      setEmail('');
      setShowAddForm(false);
      await loadUsers();
    }
    setLoading(false);
  };

  const handleDelete = async (id: string) => {
    const success = await deleteUserProfile(id);
    if (success) {
      await loadUsers();
    }
  };

  const activeOperators = users.filter((u) => u.status === 'online').length;
  const totalScansByUsers = users.reduce((acc, u) => acc + (u.scansToday || 0), 0);
  const totalThreatsBlocked = users.reduce((acc, u) => acc + (u.threatsBlocked || 0), 0);

  return (
    <div className="space-y-8">
      {/* Top statistics overview cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <StatCard
          title="Active Operators"
          value={activeOperators.toString()}
          icon={Users}
          trend={`${users.length} registered`}
          trendDirection="neutral"
          trendLabel="system accounts"
          iconColor="text-cyber-blue"
        />
        <StatCard
          title="Operator Scans"
          value={totalScansByUsers.toString()}
          icon={Database}
          trend={`${totalThreatsBlocked} threats`}
          trendDirection="neutral"
          trendLabel="blocked by users"
          iconColor="text-cyber-yellow"
        />
        <StatCard
          title="System Operators"
          value={users.length.toString()}
          icon={AlertTriangle}
          trend="Production"
          trendDirection="up"
          trendLabel="access verified"
          iconColor="text-cyber-green"
        />
      </div>

      {/* Main Admin Section */}
      <GlassCard className="w-full" hoverEffect={false}>
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 border-b border-cyber-inner-border pb-4 mb-6">
          <div>
            <h3 className="text-sm font-semibold text-cyber-text font-cyber tracking-wide">
              User Activity Monitor
            </h3>
            <p className="text-[10px] text-cyber-muted font-light mt-0.5">Audit log of system operators and analytics queries</p>
          </div>
          
          <CyberButton
            variant="outline"
            size="sm"
            onClick={() => setShowAddForm(!showAddForm)}
            className="flex items-center gap-2 cursor-pointer w-full sm:w-auto"
          >
            <UserPlus className="w-4 h-4" /> Add Operator
          </CyberButton>
        </div>

        {/* Add Operator collapsible form */}
        {showAddForm && (
          <form onSubmit={handleAddUser} className="mb-6 p-4 rounded-xl bg-cyber-inner border border-cyber-inner-border grid grid-cols-1 md:grid-cols-3 gap-4 items-end animate-in slide-in-from-top-2 duration-200">
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-cyber-muted">Operator Email</label>
              <CyberInput
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@company.com"
                required
                className="py-2 text-xs rounded-xl"
              />
            </div>
            
            <div className="space-y-1">
              <label className="text-[10px] font-semibold text-cyber-muted">Security Role</label>
              <select
                value={role}
                onChange={(e: any) => setRole(e.target.value)}
                className="w-full bg-cyber-input border border-cyber-inner-border text-xs text-cyber-text rounded-xl py-2 px-3 focus:outline-none focus:border-cyber-blue/50 focus:ring-1 focus:ring-cyber-blue/20 h-10 transition duration-300"
              >
                <option value="user">User</option>
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </select>
            </div>

            <div className="flex gap-2">
              <CyberButton
                type="submit"
                loading={loading}
                className="flex-1 h-10 py-0 text-xs shadow-glow"
              >
                Create Account
              </CyberButton>
              <CyberButton
                type="button"
                variant="outline"
                onClick={() => setShowAddForm(false)}
                className="h-10 py-0 text-xs"
              >
                Cancel
              </CyberButton>
            </div>
          </form>
        )}

        {/* Activity Table */}
        <div className="overflow-x-auto w-full">
          <table className="w-full border-collapse text-left text-xs font-light">
            <thead>
              <tr className="border-b border-cyber-inner-border text-cyber-muted font-medium">
                <th className="pb-4 pr-4 pl-2 w-20">Operator ID</th>
                <th className="pb-4 pr-4">Email</th>
                <th className="pb-4 pr-4 w-28 text-center">Scans Today</th>
                <th className="pb-4 pr-4 w-32 text-center">Threats Blocked</th>
                <th className="pb-4 pr-4 w-32">Last Active</th>
                <th className="pb-4 pr-4 w-24">Status</th>
                <th className="pb-4 pr-2 text-right w-20">Action</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-white/5 text-cyber-text font-light">
              {users.map((u) => (
                <tr key={u.userId} className="hover:bg-cyber-inner transition duration-200">
                  <td className="py-4 pr-4 pl-2 font-mono text-cyber-muted">
                    {u.userId}
                  </td>
                  <td className="py-4 pr-4 text-cyber-text font-medium">
                    <div className="flex flex-col">
                      <span>{u.email}</span>
                      <span className="text-[9px] uppercase tracking-wider text-cyber-blue font-semibold mt-0.5">{u.role}</span>
                    </div>
                  </td>
                  <td className="py-4 pr-4 text-center font-semibold text-cyber-text">
                    {u.scansToday}
                  </td>
                  <td className="py-4 pr-4 text-center">
                    <span className="px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 font-bold border border-red-500/20 text-[10px]">
                      {u.threatsBlocked}
                    </span>
                  </td>
                  <td className="py-4 pr-4 text-cyber-muted">
                    {u.lastActive}
                  </td>
                  <td className="py-4 pr-4">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          u.status === 'online'
                            ? 'bg-cyber-green'
                            : u.status === 'away'
                            ? 'bg-cyber-yellow'
                            : 'bg-gray-500'
                        }`}
                      ></span>
                      <span className="capitalize">{u.status}</span>
                    </div>
                  </td>
                  <td className="py-4 pr-2 text-right">
                    <button
                      onClick={() => handleDelete(u.userId)}
                      className="p-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 hover:text-red-300 border border-red-500/10 cursor-pointer transition"
                      title="Deactivate Operator Account"
                      disabled={u.userId === '001'} // protect main admin account
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </GlassCard>
    </div>
  );
};
export default UsersPage;
