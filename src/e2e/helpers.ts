import { config } from 'dotenv';
import { resolve } from 'node:path';

// Load .env.e2e from project root
config({ path: resolve(import.meta.dirname, '../../.env.e2e') });

export const ENV = {
  VERCEL_TOKEN: process.env.VERCEL_TOKEN,
  VERCEL_PROJECT_ID: process.env.VERCEL_PROJECT_ID,
  VERCEL_TEAM_ID: process.env.VERCEL_TEAM_ID,
  E2B_API_KEY: process.env.E2B_API_KEY,
  DAYTONA_API_KEY: process.env.DAYTONA_API_KEY,
  DAYTONA_API_URL: process.env.DAYTONA_API_URL,
  DAYTONA_TARGET: process.env.DAYTONA_TARGET,
  CLOUDFLARE_WORKER_URL: process.env.CLOUDFLARE_WORKER_URL,
  CLOUDFLARE_API_TOKEN: process.env.CLOUDFLARE_API_TOKEN,
  BLAXEL_API_KEY: process.env.BLAXEL_API_KEY,
  SPRITES_TOKEN: process.env.SPRITES_TOKEN,
  SPRITES_ORG: process.env.SPRITES_ORG,
  SPRITES_NAME: process.env.SPRITES_NAME,
  FLY_API_TOKEN: process.env.FLY_API_TOKEN,
};
