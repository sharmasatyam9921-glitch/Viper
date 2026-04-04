-- Add Hydra brute force settings columns
ALTER TABLE "projects" ADD COLUMN "hydra_enabled" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "projects" ADD COLUMN "hydra_threads" INTEGER NOT NULL DEFAULT 16;
ALTER TABLE "projects" ADD COLUMN "hydra_wait_between_connections" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "projects" ADD COLUMN "hydra_connection_timeout" INTEGER NOT NULL DEFAULT 32;
ALTER TABLE "projects" ADD COLUMN "hydra_stop_on_first_found" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "projects" ADD COLUMN "hydra_extra_checks" TEXT NOT NULL DEFAULT 'nsr';
ALTER TABLE "projects" ADD COLUMN "hydra_verbose" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "projects" ADD COLUMN "hydra_max_wordlist_attempts" INTEGER NOT NULL DEFAULT 3;

-- Add execute_hydra to existing projects' tool phase maps
UPDATE projects
SET agent_tool_phase_map = jsonb_set(
  agent_tool_phase_map::jsonb,
  '{execute_hydra}',
  '["exploitation","post_exploitation"]'::jsonb
)
WHERE agent_tool_phase_map IS NOT NULL
  AND NOT (agent_tool_phase_map::jsonb ? 'execute_hydra');

-- Update the column default to include execute_hydra
ALTER TABLE "projects" ALTER COLUMN "agent_tool_phase_map" SET DEFAULT '{"query_graph":["informational","exploitation","post_exploitation"],"web_search":["informational","exploitation","post_exploitation"],"execute_curl":["informational","exploitation","post_exploitation"],"execute_naabu":["informational","exploitation","post_exploitation"],"execute_nmap":["informational","exploitation","post_exploitation"],"execute_nuclei":["informational","exploitation","post_exploitation"],"kali_shell":["informational","exploitation","post_exploitation"],"execute_code":["exploitation","post_exploitation"],"execute_hydra":["exploitation","post_exploitation"],"metasploit_console":["exploitation","post_exploitation"],"msf_restart":["exploitation","post_exploitation"]}';
