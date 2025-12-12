
// File: index.js

// --- Imports ---
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy; // NEW: Import Local Strategy
const bcrypt = require('bcryptjs'); // NEW: Import bcrypt for hashing
require('dotenv').config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.SERVER_PORT || 5000;

// --- Middleware Setup ---
// Updated CORS Configuration
app.use(cors({
  origin: function (origin, callback) {
    // 1. Allow requests with no origin (like server-to-server calls or mobile apps)
    if (!origin) return callback(null, true);

    // 2. Allow specific allowed domains (Localhost + Production)
    const allowedOrigins = [
      process.env.CLIENT_ORIGIN, 
      'http://localhost:3000'
    ];
    
    // 3. CHECK: Is it a main domain OR a Cloudflare Preview?
    // This Regex allows https://<anything>.mednet-frontend.pages.dev
    const isPreview = origin.endsWith('.mednet-frontend.pages.dev') || origin.endsWith('.pages.dev');

    if (allowedOrigins.indexOf(origin) !== -1 || isPreview) {
      callback(null, true);
    } else {
      console.log("Blocked by CORS:", origin); // Helpful for debugging logs
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Keep this true for cookies/sessions
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'a_secure_default_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
    sameSite: 'lax',
  },
}));

// Passport Setup
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Serialization ---
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// --- STRATEGY 1: Google OAuth ---
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${process.env.SERVER_URL || 'http://localhost:8000'}/api/auth/google/callback`,
},
async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await prisma.user.findUnique({
      where: { googleId: profile.id },
    });

    if (!user) {
      // Check if email already exists (e.g. they signed up with password first)
      const existingEmailUser = await prisma.user.findUnique({
        where: { email: profile.emails[0].value }
      });

      if (existingEmailUser) {
        // Link Google account to existing email account
        user = await prisma.user.update({
          where: { id: existingEmailUser.id },
          data: { googleId: profile.id }
        });
      } else {
        // Create new user
        user = await prisma.user.create({
          data: {
            googleId: profile.id,
            email: profile.emails[0].value,
            name: profile.displayName,
          },
        });
      }
    }
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// --- STRATEGY 2: Local (Email/Password) ---
passport.use(new LocalStrategy({
    usernameField: 'email', // Use email as the username
    passwordField: 'password'
  }, 
  async (email, password, done) => {
    try {
      // 1. Find user
      const user = await prisma.user.findUnique({ where: { email } });
      
      // 2. Check if user exists and has a password
      if (!user || !user.passwordHash) {
        return done(null, false, { message: 'Invalid email or password' });
      }

      // 3. Compare passwords
      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Invalid email or password' });
      }
    } catch (err) {
      return done(err);
    }
  }
));

// --- Auth Routes ---

// 1. Google Routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${process.env.CLIENT_ORIGIN}/login` }),
  (req, res) => res.redirect(`${process.env.CLIENT_ORIGIN}/home`)
);

// 2. Email/Password Signup Route
app.post('/api/auth/signup', async (req, res, next) => {
  const { name, email, password } = req.body;
  try {
    // Check existing
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ message: 'Email already in use' });

    // Hash Password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create User
    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        passwordHash: hashedPassword // Matches schema.prisma 
      }
    });

    // Auto-login after signup
    req.login(newUser, (err) => {
      if (err) return next(err);
      res.status(201).json({ message: 'Signup successful', user: newUser });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 3. Email/Password Login Route
app.post('/api/auth/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(400).json({ message: info?.message || 'Login failed' });
    
    req.login(user, (err) => {
      if (err) return next(err);
      return res.status(200).json({ message: 'Login successful', user });
    });
  })(req, res, next);
});

// 4. Shared Routes (Me/Logout)
app.get('/api/auth/me', (req, res) => {
  if (req.user) res.status(200).json(req.user);
  else res.status(401).json({ message: 'Not authenticated' });
});

app.post('/api/auth/logout', (req, res, next) => {
  req.logout((err) => { 
    if (err) return next(err); 
    req.session.destroy(() => { 
      res.clearCookie('connect.sid'); 
      res.status(200).json({ message: 'Logged out successfully' });
    });
  });
});

// 5. Chat Logging (Protected)
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ message: 'Unauthorized' });
}

app.post('/api/chat/log', ensureAuthenticated, async (req, res) => {
  const { type, content } = req.body;
  try {
    const logEntry = await prisma.chatMessage.create({
      data: { userId: req.user.id, type, content },
    });
    res.status(201).json(logEntry);
  } catch (error) {
    res.status(500).json({ error: 'Failed to log chat activity' });
  }
});

// Initialize Groq AI
const Groq = require('groq-sdk');

// Medical chatbot endpoint with Groq AI (LLaMA 3.1)
app.post('/api/chat/message', ensureAuthenticated, async (req, res) => {
  const { message } = req.body;
  
  try {
    // Check if Groq API key is configured
    if (!process.env.GROQ_API_KEY) {
      return res.status(503).json({ 
        error: 'Groq API not configured',
        message: 'Please add GROQ_API_KEY to your .env file'
      });
    }

    // Initialize Groq client with API key
    const client = new Groq({ apiKey: process.env.GROQ_API_KEY });

    // Save user message
    await prisma.chatMessage.create({
      data: { 
        userId: req.user.id, 
        type: 'user_message', 
        content: message 
      },
    });

    // Get user's last prediction for context
    const lastPrediction = await prisma.prediction.findFirst({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' }
    });

    // Get last 6 chat exchanges for conversation context (reduced to avoid repetition)
    const recentChats = await prisma.chatMessage.findMany({
      where: { userId: req.user.id },
      orderBy: { timestamp: 'desc' },
      take: 12 // 12 messages = 6 exchanges
    });

    // Build conversation history with truncated bot responses to avoid repetition
    const conversationHistory = recentChats
      .reverse()
      .map(chat => {
        if (chat.type === 'user_message') {
          return `User: ${chat.content}`;
        } else {
          // Truncate bot responses to first 200 chars to show context without overwhelming
          const truncated = chat.content.length > 200 
            ? chat.content.substring(0, 200) + '... [previous response truncated]'
            : chat.content;
          return `Assistant: ${truncated}`;
        }
      })
      .join('\n');

    // Create system context with structured formatting requirements
    let systemContext = `You are a medical AI assistant specializing in cardiology and ECG analysis, particularly Atrial Fibrillation (AF) detection. 

CRITICAL FORMATTING REQUIREMENT: You MUST structure ALL responses using this exact format:

## [Main Topic Title]

### Overview
[Brief 1-2 sentence introduction to the topic]

### Key Points
• [First key point with explanation]
• [Second key point with explanation]
• [Third key point with explanation]

### Detailed Explanation
[More detailed information in short, digestible paragraphs. Keep each paragraph to 2-3 sentences maximum.]

[Another short paragraph if needed for clarity.]

### Your ECG Results
**Analysis Date:** ${lastPrediction ? lastPrediction.createdAt.toLocaleDateString() : 'No analysis yet'}
**Result:** ${lastPrediction ? lastPrediction.prediction : 'N/A'}
**Confidence:** ${lastPrediction ? (lastPrediction.confidence * 100).toFixed(1) + '%' : 'N/A'}
**AF Probability:** ${lastPrediction ? (lastPrediction.probabilityAf * 100).toFixed(1) + '%' : 'N/A'}
**Normal Probability:** ${lastPrediction ? (lastPrediction.probabilityNormal * 100).toFixed(1) + '%' : 'N/A'}

### What This Means For You
[Personalized interpretation based on their results in 2-3 clear sentences]

### Recommendations
• [Specific recommendation 1]
• [Specific recommendation 2]
• [Specific recommendation 3]

### ⚠️ Medical Disclaimer
**Important:** This is AI-generated information for educational purposes only, not medical advice. Always consult with a qualified healthcare professional for diagnosis, treatment decisions, and medical guidance.

---

Your expertise includes:
- ECG interpretation and analysis
- Atrial Fibrillation symptoms, causes, diagnosis, and management
- Heart rhythm disorders and arrhythmias
- Cardiovascular risk factors
- Heart health and wellness advice
- Medical terminology explained in simple, clear language

FORMATTING RULES YOU MUST FOLLOW:
1. Always use ## for main topic titles
2. Use ### for section headers
3. Use • for bullet points (not dashes)
4. Use **text** for emphasis and key terms
5. Keep paragraphs short (2-3 sentences max)
6. Always include the "Medical Disclaimer" section at the end
7. If ECG results exist, always include the "Your ECG Results" section
8. Use line breaks between sections for readability
`;

    // Add last prediction context if available  
    if (lastPrediction) {
      systemContext += `\n\nPATIENT CONTEXT (MUST use in "Your ECG Results" and "What This Means For You" sections):
- File: ${lastPrediction.filename}
- Date: ${lastPrediction.createdAt.toLocaleDateString()}
- Result: ${lastPrediction.prediction}
- Confidence: ${(lastPrediction.confidence * 100).toFixed(1)}%
- AF Probability: ${(lastPrediction.probabilityAf * 100).toFixed(1)}%
- Normal Probability: ${(lastPrediction.probabilityNormal * 100).toFixed(1)}%`;
    }

    // Build a more focused prompt that emphasizes the user query
    const userPrompt = `${conversationHistory ? '\n=== PREVIOUS CONVERSATION (FOR CONTEXT ONLY) ===\n' + conversationHistory + '\n=== END OF PREVIOUS CONVERSATION ===\n\n' : ''}
╔═══════════════════════════════════════════════════════════════╗
║          CURRENT USER QUESTION (ANSWER THIS NOW)              ║
╚═══════════════════════════════════════════════════════════════╝

${message}

╔═══════════════════════════════════════════════════════════════╗
║                    IMPORTANT INSTRUCTIONS                      ║
╚═══════════════════════════════════════════════════════════════╝

1. READ THE CURRENT USER QUESTION ABOVE CAREFULLY
2. Generate a FRESH, UNIQUE response specifically answering THAT question
3. DO NOT copy or repeat content from previous responses
4. Use the conversation history ONLY for context, not to repeat information
5. Focus on what the user is asking RIGHT NOW in their current question
6. If the question is new or different, provide a completely new answer
7. Apply the structured formatting template to YOUR NEW answer

NOW ANSWER THE CURRENT USER QUESTION ABOVE:`;

    // Generate response from Groq using LLaMA 3.1
    const completion = await client.chat.completions.create({
      model: "llama-3.1-8b-instant",
      messages: [
        {
          role: "system",
          content: systemContext
        },
        {
          role: "user",
          content: userPrompt
        }
      ],
      temperature: 1,
      max_tokens: 1024,
      top_p: 1,
      stream: false
    });

    const botResponse = completion.choices[0]?.message?.content || "I apologize, but I couldn't generate a response. Please try again.";

    // Save bot response
    await prisma.chatMessage.create({
      data: { 
        userId: req.user.id, 
        type: 'bot_response', 
        content: botResponse 
      },
    });

    // Clean up old messages (keep only last 20)
    const allChats = await prisma.chatMessage.findMany({
      where: { userId: req.user.id },
      orderBy: { timestamp: 'desc' }
    });
    
    if (allChats.length > 20) {
      const idsToDelete = allChats.slice(20).map(chat => chat.id);
      await prisma.chatMessage.deleteMany({
        where: { id: { in: idsToDelete } }
      });
    }

    res.json({ 
      response: botResponse,
      hasContext: !!lastPrediction
    });

  } catch (error) {
    console.error('Chatbot error:', error);
    res.status(500).json({ 
      error: 'Failed to generate response', 
      details: error.message 
    });
  }
});

// Get chat history for user
app.get('/api/chat/history', ensureAuthenticated, async (req, res) => {
  try {
    const chatHistory = await prisma.chatMessage.findMany({
      where: { userId: req.user.id },
      orderBy: { timestamp: 'asc' },
      take: 20
    });
    res.json(chatHistory);
  } catch (error) {
    console.error('Chat history fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

// 6. ECG Prediction Routes
const multer = require('multer');
const FormData = require('form-data');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

// Configure multer for file uploads (memory storage)
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 } // 200MB limit
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// CSV Preview endpoint (single file)
app.post('/api/ecg/preview', ensureAuthenticated, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Parse CSV for preview
    const csvText = req.file.buffer.toString('utf-8');
    const lines = csvText.split('\n').filter(line => line.trim()).slice(0, 1000);
    
    // Parse first 1000 values for preview
    const values = [];
    for (const line of lines) {
      const parts = line.split(/[\s,]+/).map(v => parseFloat(v)).filter(v => !isNaN(v));
      values.push(...parts);
      if (values.length >= 1000) break;
    }

    res.json({
      status: 'success',
      preview: values.slice(0, 1000),
      totalPoints: values.length,
      filename: req.file.originalname
    });
  } catch (error) {
    console.error('Preview error:', error);
    res.status(500).json({ error: 'Failed to preview file' });
  }
});

// CSV Preview endpoint (multiple files)
app.post('/api/ecg/preview-multiple', ensureAuthenticated, upload.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    const previews = [];
    
    for (const file of req.files) {
      try {
        // Parse CSV for preview
        const csvText = file.buffer.toString('utf-8');
        const lines = csvText.split('\n').filter(line => line.trim()).slice(0, 1000);
        
        // Parse first 1000 values for preview
        const values = [];
        for (const line of lines) {
          const parts = line.split(/[\s,]+/).map(v => parseFloat(v)).filter(v => !isNaN(v));
          values.push(...parts);
          if (values.length >= 1000) break;
        }

        previews.push({
          status: 'success',
          preview: values.slice(0, 1000),
          totalPoints: values.length,
          filename: file.originalname
        });
      } catch (error) {
        previews.push({
          status: 'error',
          error: 'Failed to parse file',
          filename: file.originalname
        });
      }
    }

    res.json({
      status: 'success',
      count: req.files.length,
      previews
    });
  } catch (error) {
    console.error('Preview error:', error);
    res.status(500).json({ error: 'Failed to preview files' });
  }
});

// Prediction endpoint - proxy to model API (single file)
app.post('/api/ecg/predict', ensureAuthenticated, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const modelApiUrl = process.env.MODEL_API_URL || 'http://localhost:8000';
    
    // Create form data to send to model API
    const formData = new FormData();
    formData.append('file', req.file.buffer, {
      filename: req.file.originalname,
      contentType: req.file.mimetype
    });

    // Forward request to model API
    const response = await fetch(`${modelApiUrl}/predict`, {
      method: 'POST',
      body: formData,
      headers: formData.getHeaders()
    });

    if (!response.ok) {
      throw new Error(`Model API error: ${response.status}`);
    }

    const result = await response.json();
    
    // Log prediction to database with CSV data for visualization
    try {
      // Parse CSV file to extract data for graph visualization
      // Store exactly 1000 points to match the preview graph display
      let csvData = null;
      try {
        const csvText = req.file.buffer.toString('utf-8');
        const lines = csvText.trim().split('\n').filter(line => line.trim());
        const allValues = [];
        
        // Extract all numeric values from CSV until we have 1000 values
        for (const line of lines) {
          const parts = line.trim().split(/[\s,]+/).map(v => parseFloat(v)).filter(v => !isNaN(v));
          allValues.push(...parts);
          if (allValues.length >= 1000) break;
        }
        
        // Create data points with time indices
        const dataPoints = allValues.slice(0, 1000).map((value, index) => ({
          time: index,
          value: value
        }));
        
        if (dataPoints.length > 0) {
          csvData = JSON.stringify(dataPoints);
        }
      } catch (parseError) {
        console.error('[CSV Parse Error]:', parseError);
      }
      
      const predictionData = {
        userId: req.user.id,
        filename: req.file.originalname,
        prediction: result.prediction || 'Unknown',
        confidence: result.confidence || 0,
        probabilityAf: result.probability_af || 0,
        probabilityNormal: result.probability_normal || 0,
        csvData: csvData
      };
      
      const savedPrediction = await prisma.prediction.create({
        data: predictionData
      });
    } catch (dbError) {
      console.error('[DB Error] Failed to log prediction:', dbError);
      console.error('[DB Error] Full error details:', JSON.stringify(dbError, null, 2));
      // Don't fail the request if logging fails
    }

    res.json(result);
  } catch (error) {
    console.error('Prediction error:', error);
    res.status(500).json({ 
      error: 'Failed to get prediction', 
      details: error.message 
    });
  }
});

// Prediction endpoint - proxy to model API (multiple files)
app.post('/api/ecg/predict-multiple', ensureAuthenticated, upload.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    const modelApiUrl = process.env.MODEL_API_URL || 'http://localhost:8000';
    const results = [];
    
    for (const file of req.files) {
      try {
        // Create form data to send to model API
        const formData = new FormData();
        formData.append('file', file.buffer, {
          filename: file.originalname,
          contentType: file.mimetype
        });

        // Forward request to model API
        const response = await fetch(`${modelApiUrl}/predict`, {
          method: 'POST',
          body: formData,
          headers: formData.getHeaders()
        });

        if (!response.ok) {
          throw new Error(`Model API error: ${response.status}`);
        }

        const result = await response.json();
        
        // Log prediction to database with CSV data for visualization
        try {
          // Parse CSV file to extract data for graph visualization
          // Store exactly 1000 points to match the preview graph display
          let csvData = null;
          try {
            const csvText = file.buffer.toString('utf-8');
            const lines = csvText.trim().split('\n').filter(line => line.trim());
            const allValues = [];
            
            // Extract all numeric values from CSV until we have 1000 values
            for (const line of lines) {
              const parts = line.trim().split(/[\s,]+/).map(v => parseFloat(v)).filter(v => !isNaN(v));
              allValues.push(...parts);
              if (allValues.length >= 1000) break;
            }
            
            // Create data points with time indices
            const dataPoints = allValues.slice(0, 1000).map((value, index) => ({
              time: index,
              value: value
            }));
            
            if (dataPoints.length > 0) {
              csvData = JSON.stringify(dataPoints);
            }
          } catch (parseError) {
            console.error(`[CSV Parse Multi Error] ${file.originalname}:`, parseError);
          }
          
          const predictionData = {
            userId: req.user.id,
            filename: file.originalname,
            prediction: result.prediction || 'Unknown',
            confidence: result.confidence || 0,
            probabilityAf: result.probability_af || 0,
            probabilityNormal: result.probability_normal || 0,
            csvData: csvData
          };
          
          const savedPrediction = await prisma.prediction.create({
            data: predictionData
          });
        } catch (dbError) {
          console.error(`[DB Error Multi] Failed to log prediction for ${file.originalname}:`, dbError);
          console.error('[DB Error Multi] Full error details:', JSON.stringify(dbError, null, 2));
          // Don't fail the request if logging fails
        }

        results.push({
          filename: file.originalname,
          ...result
        });
      } catch (error) {
        results.push({
          filename: file.originalname,
          status: 'error',
          error: error.message
        });
      }
    }

    res.json({
      status: 'success',
      count: req.files.length,
      results
    });
  } catch (error) {
    console.error('Prediction error:', error);
    res.status(500).json({ 
      error: 'Failed to get predictions', 
      details: error.message 
    });
  }
});

// Get user's prediction history
app.get('/api/ecg/history', ensureAuthenticated, async (req, res) => {
  try {
    const predictions = await prisma.prediction.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' },
      take: 50
    });
    
    // Log csvData status for debugging
    
    
    res.json(predictions);
  } catch (error) {
    console.error('History fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch prediction history' });
  }
});

// Debug endpoint to check csvData storage
app.get('/api/ecg/debug/:predictionId', ensureAuthenticated, async (req, res) => {
  try {
    const prediction = await prisma.prediction.findUnique({
      where: { 
        id: req.params.predictionId,
        userId: req.user.id  // Ensure user owns this prediction
      }
    });
    
    if (!prediction) {
      return res.status(404).json({ error: 'Prediction not found' });
    }
    
    res.json({
      id: prediction.id,
      filename: prediction.filename,
      hasCsvData: !!prediction.csvData,
      csvDataLength: prediction.csvData ? prediction.csvData.length : 0,
      csvDataSample: prediction.csvData ? prediction.csvData.substring(0, 200) + '...' : null,
      createdAt: prediction.createdAt
    });
  } catch (error) {
    console.error('Debug fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch prediction debug info' });
  }
});

// Global error handler - ensures all errors return JSON
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});
app.get('/', (req, res) => {
  res.send('✅ Backend is running successfully!');
});

// 404 handler - ensures unknown routes return JSON
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
