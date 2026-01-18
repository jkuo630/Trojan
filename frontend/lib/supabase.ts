import { createClient } from "@supabase/supabase-js";

const supabaseUrl = "https://jmdmrlzfnjjbgyvxciix.supabase.co";
const supabaseAnonKey = "sb_publishable_QuGS5we_2BOSRKZ8_69CzA_DJ5yIU-8";

export const supabase = createClient(supabaseUrl, supabaseAnonKey);
