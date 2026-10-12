# Orbit Chat

A responsive, real-time messaging web application powered by
Cloudflare Workers, D1 and Durable Objects.

## Features

- Username/password registration and login
- Secure, HTTP-only session cookies
- Password hashing with PBKDF2
- Unique usernames
- Search users by username
- One-to-one conversations
- Real-time messaging with WebSockets
- Persistent message history
- Responsive mobile and desktop interface
- Cloudflare static assets hosting

## Requirements

- Node.js and npm
- A Cloudflare account
- Wrangler CLI
- A Cloudflare D1 database

## Setup

1. Install dependencies:

   npm install

2. Create the D1 database:

   npx wrangler d1 create orbit-chat-db

3. Copy the database ID from the command output into
   `wrangler.jsonc`, replacing the placeholder.

4. Apply the database migration:

   npx wrangler d1 migrations apply orbit-chat-db --remote

5. Start development:

   npm run dev

6. Deploy:

   npm run deploy

## Important

This is an initial testing version. Test authentication,
message persistence, reconnects and access controls before
a public launch.

End-to-end encryption, attachments, voice/video calls,
push notifications, groups and account recovery are not
implemented in this initial version.
