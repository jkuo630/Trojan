import { createClient } from "@supabase/supabase-js";
import { cookies } from "next/headers";

const supabaseUrl = "https://jmdmrlzfnjjbgyvxciix.supabase.co";
const supabaseAnonKey = "sb_publishable_QuGS5we_2BOSRKZ8_69CzA_DJ5yIU-8";

export function createServerClient() {
  const cookieStore = cookies();
  
  return createClient(supabaseUrl, supabaseAnonKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options)
          );
        } catch {
          // The `setAll` method was called from a Server Component.
          // This can be ignored if you have middleware refreshing
          // user sessions.
        }
      },
    },
  });
}
