-- Add chisel tunnel toggle (multi-port alternative to ngrok)
ALTER TABLE "projects" ADD COLUMN "agent_chisel_tunnel_enabled" BOOLEAN NOT NULL DEFAULT false;
