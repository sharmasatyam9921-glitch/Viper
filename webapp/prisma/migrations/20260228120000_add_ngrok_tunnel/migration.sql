-- Add ngrok tunnel toggle for reverse shell tunneling
ALTER TABLE "projects" ADD COLUMN "agent_ngrok_tunnel_enabled" BOOLEAN NOT NULL DEFAULT false;
