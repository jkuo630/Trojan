import { supabase } from "./supabase";

/**
 * Get the current user's GitHub access token.
 * This token can be used to make authenticated GitHub API calls.
 */
export async function getGitHubToken(): Promise<string | null> {
  // Get the current session
  const { data, error } = await supabase.auth.getSession();

  if (error || !data.session) {
    console.error("No active session found");
    return null;
  }

  // provider_token contains the GitHub OAuth token
  const githubToken = data.session.provider_token;

  if (!githubToken) {
    console.error("No GitHub token found in session");
    return null;
  }

  return githubToken;
}

/**
 * Get the current user's information including email and username.
 */
export async function getCurrentUser() {
  const { data, error } = await supabase.auth.getUser();

  if (error || !data.user) {
    return null;
  }

  return {
    id: data.user.id,
    email: data.user.email,
    username: data.user.user_metadata?.user_name, // GitHub username
    avatar: data.user.user_metadata?.avatar_url,
  };
}
