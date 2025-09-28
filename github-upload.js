import { Octokit } from '@octokit/rest';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';

let connectionSettings;

async function getAccessToken() {
  if (connectionSettings && connectionSettings.settings.expires_at && new Date(connectionSettings.settings.expires_at).getTime() > Date.now()) {
    return connectionSettings.settings.access_token;
  }
  
  const hostname = process.env.REPLIT_CONNECTORS_HOSTNAME
  const xReplitToken = process.env.REPL_IDENTITY 
    ? 'repl ' + process.env.REPL_IDENTITY 
    : process.env.WEB_REPL_RENEWAL 
    ? 'depl ' + process.env.WEB_REPL_RENEWAL 
    : null;

  if (!xReplitToken) {
    throw new Error('X_REPLIT_TOKEN not found for repl/depl');
  }

  connectionSettings = await fetch(
    'https://' + hostname + '/api/v2/connection?include_secrets=true&connector_names=github',
    {
      headers: {
        'Accept': 'application/json',
        'X_REPLIT_TOKEN': xReplitToken
      }
    }
  ).then(res => res.json()).then(data => data.items?.[0]);

  const accessToken = connectionSettings?.settings?.access_token || connectionSettings.settings?.oauth?.credentials?.access_token;

  if (!connectionSettings || !accessToken) {
    throw new Error('GitHub not connected');
  }
  return accessToken;
}

async function getUncachableGitHubClient() {
  const accessToken = await getAccessToken();
  return new Octokit({ auth: accessToken });
}

async function createGitHubRepository(repoName = 'zeroday-academy-labs') {
  try {
    console.log('🚀 Creating GitHub repository...');
    
    const octokit = await getUncachableGitHubClient();
    
    // Get authenticated user
    const { data: user } = await octokit.rest.users.getAuthenticated();
    console.log(`✅ Authenticated as: ${user.login}`);
    
    // Check if repository already exists
    try {
      await octokit.rest.repos.get({
        owner: user.login,
        repo: repoName,
      });
      console.log(`⚠️  Repository ${repoName} already exists!`);
      console.log(`🔗 Repository URL: https://github.com/${user.login}/${repoName}`);
      return { owner: user.login, repo: repoName };
    } catch (error) {
      if (error.status !== 404) throw error;
    }
    
    // Create new repository
    const { data: repo } = await octokit.rest.repos.createForAuthenticatedUser({
      name: repoName,
      description: 'Cybersecurity penetration testing training platform with separated beginner and intermediate labs',
      public: true,
      has_issues: true,
      has_projects: false,
      has_wiki: false,
    });
    
    console.log(`✅ Repository created: ${repo.html_url}`);
    return { owner: user.login, repo: repoName, url: repo.html_url };
    
  } catch (error) {
    console.error('❌ Failed to create repository:', error.message);
    throw error;
  }
}

async function uploadToGitHub() {
  try {
    const repoInfo = await createGitHubRepository();
    
    console.log('📦 Preparing files for upload...');
    
    // Configure git if needed
    try {
      execSync('git config user.email "replit@example.com"', { stdio: 'ignore' });
      execSync('git config user.name "Replit User"', { stdio: 'ignore' });
    } catch (e) {
      // Git already configured
    }
    
    // Add remote origin
    const repoUrl = `https://github.com/${repoInfo.owner}/${repoInfo.repo}.git`;
    
    try {
      execSync(`git remote remove origin`, { stdio: 'ignore' });
    } catch (e) {
      // No existing origin
    }
    
    execSync(`git remote add origin ${repoUrl}`, { stdio: 'inherit' });
    
    // Stage all files
    execSync('git add .', { stdio: 'inherit' });
    
    // Commit
    execSync('git commit -m "Initial commit: Separated beginner and intermediate labs"', { stdio: 'inherit' });
    
    // Get authenticated URL for push
    const accessToken = await getAccessToken();
    const authenticatedUrl = `https://${accessToken}@github.com/${repoInfo.owner}/${repoInfo.repo}.git`;
    
    // Push to GitHub
    console.log('📤 Uploading to GitHub...');
    execSync(`git push -u origin main --force`, { 
      stdio: 'inherit',
      env: { ...process.env, GIT_ASKPASS: 'echo', GIT_USERNAME: 'token', GIT_PASSWORD: accessToken }
    });
    
    console.log('');
    console.log('🎉 Successfully uploaded to GitHub!');
    console.log(`🔗 Repository: https://github.com/${repoInfo.owner}/${repoInfo.repo}`);
    console.log('');
    console.log('📥 To clone on your server:');
    console.log(`git clone https://github.com/${repoInfo.owner}/${repoInfo.repo}.git`);
    console.log('cd ' + repoInfo.repo);
    console.log('npm install');
    console.log('./start-beginner.sh     # For beginner labs');
    console.log('./start-intermediate.sh # For intermediate labs');
    
  } catch (error) {
    console.error('❌ Upload failed:', error.message);
    throw error;
  }
}

uploadToGitHub().catch(console.error);