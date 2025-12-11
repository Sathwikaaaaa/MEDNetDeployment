// // // import express from "express";
// // // import { PrismaClient } from "@prisma/client";
// // // import bcrypt from "bcrypt";
// // // import jwt from "jsonwebtoken";
// // // import cors from "cors";

// // // const app = express();
// // // const prisma = new PrismaClient();
// // // const PORT = 5000; // server port
// // // const JWT_SECRET = "my_super_secret_123"; // change this to something unique

// // // app.use(cors());
// // // app.use(express.json());

// // // // Helper: generate JWT token
// // // function generateToken(userId) {
// // //   return jwt.sign({ userId }, JWT_SECRET, { expiresIn: "1h" });
// // // }

// // // // Register user
// // // app.post("/register", async (req, res) => {
// // //   const { email, name, password } = req.body;
// // //   const hashedPassword = await bcrypt.hash(password, 10);
// // //   try {
// // //     const user = await prisma.user.create({
// // //       data: { email, name, password: hashedPassword }
// // //     });
// // //     res.json({ id: user.id, email: user.email, name: user.name });
// // //   } catch (err) {
// // //     res.status(400).json({ error: "User already exists" });
// // //   }
// // // });

// // // // Login user
// // // app.post("/login", async (req, res) => {
// // //   const { email, password } = req.body;
// // //   const user = await prisma.user.findUnique({ where: { email } });
// // //   if (!user) return res.status(400).json({ error: "User not found" });

// // //   const valid = await bcrypt.compare(password, user.password);
// // //   if (!valid) return res.status(400).json({ error: "Wrong password" });

// // //   const token = generateToken(user.id);
// // //   res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
// // // });

// // // // Get all users
// // // app.get("/users", async (req, res) => {
// // //   const users = await prisma.user.findMany();
// // //   res.json(users);
// // // });

// // // // Add a chat
// // // app.post("/chats", async (req, res) => {
// // //   const { userId, userMessage, assistantReply, documents } = req.body;
// // //   const chat = await prisma.chat.create({
// // //     data: { userId, userMessage, assistantReply, documents }
// // //   });
// // //   res.json(chat);
// // // });

// // // // Get all chats
// // // app.get("/chats", async (req, res) => {
// // //   const chats = await prisma.chat.findMany({ include: { user: true } });
// // //   res.json(chats);
// // // });

// // // app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));


// // // server.js

// // // 1. Import Libraries
// // require('dotenv').config(); // Load environment variables from .env file first
// // const express = require('express');
// // const session = require('express-session');
// // const passport = require('passport');
// // const GoogleStrategy = require('passport-google-oauth20').Strategy;
// // const cors = require('cors');
// // const { PrismaClient } = require('@prisma/client'); // Import Prisma

// // // 2. Initialize App and Prisma
// // const app = express();
// // const prisma = new PrismaClient(); // Create Prisma client instance
// // const PORT = process.env.PORT || 8000;

// // // 3. Middleware Setup

// // // CORS: Allow requests from your frontend
// // app.use(cors({
// //   origin: process.env.CLIENT_ORIGIN, // Allow frontend origin
// //   credentials: true, // Allow cookies to be sent
// // }));

// // // Session Management: Keeps users logged in
// // app.use(session({
// //   secret: process.env.SESSION_SECRET, // Secret key from .env
// //   resave: false,                     // Don't save session if unmodified
// //   saveUninitialized: false,           // Don't create session until something stored
// //   cookie: {
// //     maxAge: 1000 * 60 * 60 * 24 * 7, // Cookie expiration time (e.g., 7 days)
// //     secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
// //     httpOnly: true, // Prevent client-side JS from accessing the cookie
// //   }
// // }));

// // // Passport Initialization: Set up Passport
// // app.use(passport.initialize()); // Initialize Passport
// // app.use(passport.session());    // Allow Passport to use sessions

// // // 4. Passport Configuration (How Google Login Works)

// // passport.use(new GoogleStrategy(
// //   {
// //     clientID: process.env.GOOGLE_CLIENT_ID,         // From .env
// //     clientSecret: process.env.GOOGLE_CLIENT_SECRET, // From .env
// //     callbackURL: `${process.env.SERVER_URL}/api/auth/google/callback` // The URL Google sends users back to
// //   },
// //   // This "verify" function runs after Google confirms the user
// //   async (accessToken, refreshToken, profile, done) => {
// //     console.log("Google profile:", profile); // Log Google profile info

// //     try {
// //       // Find user in *your* database based on their Google ID
// //       let user = await prisma.user.findUnique({
// //         where: { googleId: profile.id }
// //       });

// //       if (user) {
// //         // If user exists, pass their info to Passport
// //         console.log(`User found: ${user.email}`);
// //         return done(null, user); // null means no error, 'user' is the user data
// //       } else {
// //         // If user doesn't exist, create them in your database
// //         console.log(`Creating new user for: ${profile.emails[0].value}`);
// //         user = await prisma.user.create({
// //           data: {
// //             googleId: profile.id,
// //             email: profile.emails[0].value, // Make sure 'email' field exists in your Prisma schema
// //             name: profile.displayName,       // Make sure 'name' field exists
// //             // Add other fields as needed, e.g., avatarUrl: profile.photos[0].value
// //           }
// //         });
// //         return done(null, user); // Pass the newly created user info
// //       }
// //     } catch (err) {
// //       console.error("Error during Google strategy verification:", err);
// //       return done(err, null); // Pass error to Passport
// //     }
// //   }
// // ));

// // // --- Passport Session Management ---

// // // Stores user ID in the session cookie
// // passport.serializeUser((user, done) => {
// //   console.log("Serializing user:", user.id);
// //   done(null, user.id); // 'user.id' is the ID from YOUR database
// // });

// // // Retrieves user data from the database using the ID from the cookie
// // passport.deserializeUser(async (id, done) => {
// //   console.log("Deserializing user:", id);
// //   try {
// //     const user = await prisma.user.findUnique({ where: { id: id } }); // Find by Prisma ID
// //     done(null, user); // Attaches 'user' object to req.user
// //   } catch (err) {
// //     done(err, null);
// //   }
// // });

// // // 5. Define Authentication Routes

// // // Route 1: Start Google Login (/api/auth/google)
// // // When user clicks "Login with Google", they are sent here.
// // app.get('/api/auth/google',
// //   passport.authenticate('google', {
// //     scope: ['profile', 'email'],
// //     prompt: 'select_account' 
// //   })
// // );

// // // Route 2: Google Callback (/api/auth/google/callback)
// // // Google redirects the user back here after successful login.
// // app.get('/api/auth/google/callback',
// //   passport.authenticate('google', {
// //     // failureRedirect: `${process.env.CLIENT_ORIGIN}/login?error=true`, // Redirect on failure
// //     // successRedirect: process.env.CLIENT_ORIGIN // Redirect on success
// //     // Using custom callback instead of successRedirect to log
// //   }),
// //   (req, res) => {
// //     // Successful authentication!
// //     console.log("Google callback successful, user:", req.user?.email);
// //     // Redirect back to the frontend dashboard (or wherever you want)
// //     res.redirect(`${process.env.CLIENT_ORIGIN}/home`); // Or maybe '/dashboard' etc.
// //   }
// // );

// // // Route 3: Check Login Status (/api/auth/me)
// // // Frontend calls this to see who is logged in.
// // app.get('/api/auth/me', (req, res) => {
// //   if (req.user) {
// //     // If req.user exists (Passport put it there via deserializeUser), send user data
// //     console.log("User is authenticated:", req.user.email);
// //     res.status(200).json(req.user);
// //   } else {
// //     // If not logged in
// //     console.log("User is not authenticated");
// //     res.status(401).json({ message: 'Not authenticated' });
// //   }
// // });

// // // Route 4: Logout (/api/auth/logout)
// // app.post('/api/auth/logout', (req, res, next) => {
// //   req.logout((err) => { // req.logout is added by Passport
// //     if (err) {
// //       console.error("Logout error:", err);
// //       return next(err); // Pass error to Express error handler
// //     }
// //     req.session.destroy((destroyErr) => { // Destroy the session
// //       if (destroyErr) {
// //         console.error("Session destruction error:", destroyErr);
// //          // Still try to clear cookie and respond
// //       }
// //       res.clearCookie('connect.sid'); // Clear the session cookie
// //       console.log("User logged out successfully.");
// //       res.status(200).json({ message: 'Logged out successfully' });
// //     });
// //   });
// // });

// // // 6. Simple Test Route
// // app.get('/', (req, res) => {
// //   res.send('Backend is running!');
// // });

// // // 7. Start the Server
// // app.listen(PORT, () => {
// //   console.log(`Backend server listening on http://localhost:${PORT}`);
// // });


















// // File: index.js (COMPLETE CODE - ENSURE ALL DEPENDENCIES ARE INSTALLED)

// // --- Imports ---
// const express = require('express');
// const { PrismaClient } = require('@prisma/client');
// const cors = require('cors');
// const session = require('express-session');
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// require('dotenv').config(); // Load environment variables

// const app = express();
// const prisma = new PrismaClient();
// const PORT = process.env.SERVER_PORT || 8000; // Use port from .env or default

// // --- Middleware Setup ---
// app.use(cors({
//   origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
//   credentials: true, // Crucial for sending cookies/session ID
// }));
// app.use(express.json()); // For parsing application/json
// app.use(express.urlencoded({ extended: true }));

// // Session Setup
// app.use(session({
//   secret: process.env.SESSION_SECRET || 'a_secure_default_secret',
//   resave: false,
//   saveUninitialized: false,
//   cookie: {
//     secure: process.env.NODE_ENV === 'production', // Set to true in production with HTTPS
//     maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
//     sameSite: 'lax', // Or 'none' if running frontend/backend on different domains/ports
//   },
// }));

// // Passport Setup
// app.use(passport.initialize());
// app.use(passport.session());

// // --- Passport Serialization/Deserialization ---
// passport.serializeUser((user, done) => {
//   done(null, user.id); // Serialize user ID
// });

// passport.deserializeUser(async (id, done) => {
//   try {
//     const user = await prisma.user.findUnique({ where: { id } });
//     done(null, user); // Attach user object to req.user
//   } catch (err) {
//     done(err, null);
//   }
// });

// // --- Google Strategy ---
// passport.use(new GoogleStrategy({
//   clientID: process.env.GOOGLE_CLIENT_ID,
//   clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//   callbackURL: `${process.env.SERVER_URL || 'http://localhost:8000'}/api/auth/google/callback`,
// },
// async (accessToken, refreshToken, profile, done) => {
//   try {
//     let user = await prisma.user.findUnique({
//       where: { googleId: profile.id },
//     });

//     if (!user) {
//       // Create new user if they don't exist
//       user = await prisma.user.create({
//         data: {
//           googleId: profile.id,
//           email: profile.emails[0].value,
//           name: profile.displayName,
//         },
//       });
//     }
//     return done(null, user);
//   } catch (error) {
//     return done(error, null);
//   }
// }));

// // --- Middleware: Ensure Authenticated ---
// // NEW: Used to protect chat logging and other private routes
// function ensureAuthenticated(req, res, next) {
//   if (req.isAuthenticated()) {
//     return next();
//   }
//   res.status(401).json({ message: 'Unauthorized' });
// }

// // --- Authentication Routes ---

// // Route 1: Google OAuth Start
// app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// // Route 2: Google OAuth Callback
// app.get(
//   '/api/auth/google/callback',
//   passport.authenticate('google', {
//     failureRedirect: `${process.env.CLIENT_ORIGIN}/login`,
//   }),
//   (req, res) => {
//     // Successful authentication, redirect home.
//     res.redirect(`${process.env.CLIENT_ORIGIN}/home`);
//   }
// );

// // Route 3: Check Login Status (/api/auth/me)
// app.get('/api/auth/me', (req, res) => {
//   if (req.user) {
//     res.status(200).json(req.user);
//   } else {
//     res.status(401).json({ message: 'Not authenticated' });
//   }
// });

// // Route 4: Logout (/api/auth/logout)
// app.post('/api/auth/logout', (req, res, next) => {
//   req.logout((err) => { 
//     if (err) return next(err); 
//     req.session.destroy((destroyErr) => { 
//       if (destroyErr) console.error("Session destruction error:", destroyErr);
//       res.clearCookie('connect.sid'); 
//       res.status(200).json({ message: 'Logged out successfully' });
//     });
//   });
// });

// // --- NEW: Chat Logging API Route ---

// /**
//  * Route to log user activity (messages, actions, etc.)
//  * Requires user to be authenticated.
//  */
// app.post('/api/chat/log', ensureAuthenticated, async (req, res) => {
//   const { type, content } = req.body;
//   const userId = req.user.id; // User ID guaranteed by ensureAuthenticated middleware

//   if (!type || !content) {
//     return res.status(400).json({ error: 'Missing type or content for activity log' });
//   }

//   try {
//     const logEntry = await prisma.chatMessage.create({
//       data: {
//         userId: userId,
//         type: type,
//         content: content,
//       },
//     });
//     console.log(`Chat activity logged for user ${userId}: ${type}`);
//     res.status(201).json(logEntry); // 201 Created
//   } catch (error) {
//     console.error('Error logging chat activity:', error);
//     res.status(500).json({ error: 'Failed to log chat activity' });
//   }
// });


// // --- Server Start ---
// app.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}`);
// });






























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
app.use(cors({
  origin: process.env.CLIENT_ORIGIN || 'http://localhost:3000',
  credentials: true,
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

// 404 handler - ensures unknown routes return JSON
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.path
  });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));