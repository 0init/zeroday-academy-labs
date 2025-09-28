import { Octokit } from '@octokit/rest';
import fs from 'fs';

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
  return accessToken;
}

async function getUncachableGitHubClient() {
  const accessToken = await getAccessToken();
  return new Octokit({ auth: accessToken });
}

async function updateFixedFiles() {
  try {
    console.log('📤 Updating fixed files on GitHub...');
    
    const octokit = await getUncachableGitHubClient();
    const owner = '0init';
    const repo = 'zeroday-academy-labs';
    
    const filesToUpdate = [
      'server/beginner-routes.ts',
      'server/intermediate-routes.ts'
    ];
    
    for (const filePath of filesToUpdate) {
      try {
        // Get current file to get SHA
        const { data: currentFile } = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: filePath,
        });
        
        const content = fs.readFileSync(filePath);
        const base64Content = content.toString('base64');
        
        console.log(`📄 Updating: ${filePath}`);
        
        await octokit.rest.repos.createOrUpdateFileContents({
          owner,
          repo,
          path: filePath,
          message: `Fix: Add SPA fallback route for ${filePath.includes('beginner') ? 'beginner' : 'intermediate'} version`,
          content: base64Content,
          sha: currentFile.sha,
          branch: 'main'
        });
        
      } catch (error) {
        console.error(`❌ Failed to update ${filePath}:`, error.message);
      }
    }
    
    console.log('✅ Fixed files updated on GitHub!');
    console.log('🔗 Repository: https://github.com/0init/zeroday-academy-labs');
    
  } catch (error) {
    console.error('❌ Update failed:', error.message);
    throw error;
  }
}

updateFixedFiles().catch(console.error);