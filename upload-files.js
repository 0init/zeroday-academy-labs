import { Octokit } from '@octokit/rest';
import fs from 'fs';
import path from 'path';

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

// Get all files recursively, excluding those in .gitignore
function getAllFiles(dirPath, arrayOfFiles = [], basePath = '') {
  const gitignoreContent = fs.readFileSync('.gitignore', 'utf8').split('\n')
    .filter(line => line.trim() && !line.startsWith('#'));
  
  const files = fs.readdirSync(dirPath);

  files.forEach(function(file) {
    const fullPath = path.join(dirPath, file);
    const relativePath = path.join(basePath, file).replace(/\\/g, '/');
    
    // Skip files/directories in gitignore
    if (gitignoreContent.some(ignore => {
      const ignorePattern = ignore.trim();
      if (ignorePattern.endsWith('/')) {
        return relativePath.startsWith(ignorePattern) || relativePath === ignorePattern.slice(0, -1);
      }
      return relativePath === ignorePattern || relativePath.startsWith(ignorePattern + '/');
    })) {
      return;
    }
    
    // Skip hidden files and git directory
    if (file.startsWith('.') && file !== '.gitignore' && file !== '.env.example') {
      return;
    }

    if (fs.statSync(fullPath).isDirectory()) {
      arrayOfFiles = getAllFiles(fullPath, arrayOfFiles, relativePath);
    } else {
      arrayOfFiles.push({
        path: relativePath,
        fullPath: fullPath
      });
    }
  });

  return arrayOfFiles;
}

async function uploadAllFiles() {
  try {
    console.log('📤 Starting file upload to GitHub...');
    
    const octokit = await getUncachableGitHubClient();
    const owner = '0init';
    const repo = 'zeroday-academy-labs';
    
    // Get all files
    const allFiles = getAllFiles('.', []);
    console.log(`📁 Found ${allFiles.length} files to upload`);
    
    let uploadCount = 0;
    
    for (const fileInfo of allFiles) {
      try {
        const content = fs.readFileSync(fileInfo.fullPath);
        const base64Content = content.toString('base64');
        
        console.log(`📄 Uploading: ${fileInfo.path}`);
        
        await octokit.rest.repos.createOrUpdateFileContents({
          owner,
          repo,
          path: fileInfo.path,
          message: `Add ${fileInfo.path}`,
          content: base64Content,
          branch: 'main'
        });
        
        uploadCount++;
        
        // Small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
        
      } catch (error) {
        console.error(`❌ Failed to upload ${fileInfo.path}:`, error.message);
      }
    }
    
    console.log('');
    console.log(`🎉 Successfully uploaded ${uploadCount}/${allFiles.length} files!`);
    console.log(`🔗 Repository: https://github.com/${owner}/${repo}`);
    console.log('');
    console.log('🚀 Ready to deploy on your server:');
    console.log(`git clone https://github.com/${owner}/${repo}.git`);
    console.log(`cd ${repo}`);
    console.log('npm install');
    console.log('./start-beginner.sh     # For beginner labs');
    console.log('./start-intermediate.sh # For intermediate labs');
    
  } catch (error) {
    console.error('❌ Upload failed:', error.message);
    throw error;
  }
}

uploadAllFiles().catch(console.error);