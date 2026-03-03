#!/usr/bin/env node

/**
 * Supabase Setup Script
 * This script helps configure Supabase credentials for the Baseline frontend
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

function updateEnvFile(supabaseUrl, anonKey, serviceRoleKey) {
  const envPath = path.join(__dirname, '../.env');
  let envContent = '';
  
  // Read existing .env file
  if (fs.existsSync(envPath)) {
    envContent = fs.readFileSync(envPath, 'utf8');
  } else {
    // Create basic .env if it doesn't exist
    envContent = `# Server Configuration
PORT=8001
NODE_ENV=development

# Backend API Configuration
BACKEND_URL=http://localhost:8080

# Supabase Configuration
SUPABASE_URL=
SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=

# Redis Configuration
REDIS_URL=redis://localhost:6379
CACHE_TTL=300

# Session Configuration
SESSION_SECRET=your-session-secret-here-change-in-production

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Valid API Keys
VALID_API_KEYS=dev-api-key-1,dev-api-key-2
`;
  }
  
  // Update Supabase configuration
  envContent = envContent.replace(/SUPABASE_URL=.*/, `SUPABASE_URL=${supabaseUrl}`);
  envContent = envContent.replace(/SUPABASE_ANON_KEY=.*/, `SUPABASE_ANON_KEY=${anonKey}`);
  envContent = envContent.replace(/SUPABASE_SERVICE_ROLE_KEY=.*/, `SUPABASE_SERVICE_ROLE_KEY=${serviceRoleKey}`);
  
  // Write updated .env file
  fs.writeFileSync(envPath, envContent);
  
  console.log('✅ .env file updated successfully!');
}

async function main() {
  console.log('🔧 Baseline Supabase Setup');
  console.log('==========================\n');
  
  console.log('📋 To get your Supabase credentials:');
  console.log('1. Go to https://supabase.com/dashboard');
  console.log('2. Select your project');
  console.log('3. Go to Settings → API');
  console.log('4. Copy the Project URL and keys\n');
  
  try {
    const supabaseUrl = await question('🔗 Enter your Supabase Project URL: ');
    const anonKey = await question('🔑 Enter your Supabase Anon Key: ');
    const serviceRoleKey = await question('🔐 Enter your Supabase Service Role Key: ');
    
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
      console.log('❌ All fields are required. Please try again.');
      process.exit(1);
    }
    
    console.log('\n🔄 Updating configuration...');
    updateEnvFile(supabaseUrl, anonKey, serviceRoleKey);
    
    console.log('\n🎉 Setup complete!');
    console.log('📝 Next steps:');
    console.log('1. Restart your server: npm start');
    console.log('2. Test authentication at http://localhost:8001/signin.html');
    console.log('3. Check dashboard at http://localhost:8001/dashboard.html');
    
  } catch (error) {
    console.error('❌ Setup failed:', error.message);
  } finally {
    rl.close();
  }
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = { updateEnvFile };
