-- Supabase Row Level Security (RLS) policies for CyberNeura

-- Helper function to extract user ID or check roles
-- Under standard Supabase auth, we'd use auth.uid()
-- For Firebase auth JWT, we can map claims from the auth header, or retrieve the corresponding profile role.
CREATE OR REPLACE FUNCTION public.get_user_role(user_uuid TEXT) 
RETURNS VARCHAR AS $$
BEGIN
  RETURN (SELECT role FROM public.profiles WHERE id = user_uuid);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 1. Profiles Table Policies
CREATE POLICY "Allow users to read all profiles" 
ON public.profiles FOR SELECT 
TO authenticated 
USING (true);

CREATE POLICY "Allow users to insert/update their own profile" 
ON public.profiles FOR ALL 
TO authenticated 
USING (id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin')
WITH CHECK (id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin');

-- 2. System Settings Policies
CREATE POLICY "Allow users to view own settings" 
ON public.system_settings FOR SELECT 
TO authenticated 
USING (user_id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin');

CREATE POLICY "Allow users to edit own settings" 
ON public.system_settings FOR UPDATE 
TO authenticated 
USING (user_id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin');

-- 3. URL Scans Policies
CREATE POLICY "Allow read access to scans for authenticated users" 
ON public.url_scans FOR SELECT 
TO authenticated 
USING (true);

CREATE POLICY "Allow write access to scans for users" 
ON public.url_scans FOR INSERT 
TO authenticated 
WITH CHECK (scanned_by = auth.uid()::text OR scanned_by IS NULL);

CREATE POLICY "Allow deletes of scans for analysts and admins" 
ON public.url_scans FOR DELETE 
TO authenticated 
USING (get_user_role(auth.uid()::text) IN ('admin', 'analyst'));

-- 4. Threat Logs Policies
CREATE POLICY "Allow read access to threat logs for authenticated users" 
ON public.threat_logs FOR SELECT 
TO authenticated 
USING (true);

CREATE POLICY "Allow write/deletes to threat logs for analysts and admins" 
ON public.threat_logs FOR ALL 
TO authenticated 
USING (get_user_role(auth.uid()::text) IN ('admin', 'analyst'));

-- 5. Notifications Policies
CREATE POLICY "Allow read/write of own notifications" 
ON public.notifications FOR SELECT 
TO authenticated 
USING (user_id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin');

CREATE POLICY "Allow update of own notifications" 
ON public.notifications FOR UPDATE 
TO authenticated 
USING (user_id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin');

-- 6. Chat History Policies
CREATE POLICY "Allow read/write of own chat history" 
ON public.chat_history FOR ALL 
TO authenticated 
USING (user_id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin')
WITH CHECK (user_id = auth.uid()::text OR get_user_role(auth.uid()::text) = 'admin');

-- 7. Feedback Policies
CREATE POLICY "Allow read/write feedback" 
ON public.feedback FOR SELECT 
TO authenticated 
USING (true);

CREATE POLICY "Allow insert feedback for users" 
ON public.feedback FOR INSERT 
TO authenticated 
WITH CHECK (user_id = auth.uid()::text);
