-- Add execute_code to informational phase for all existing projects
-- Uses jsonb_set to update only the execute_code entry, preserving other user customizations

UPDATE projects
SET agent_tool_phase_map = jsonb_set(
  agent_tool_phase_map::jsonb,
  '{execute_code}',
  '["informational", "exploitation", "post_exploitation"]'
)
WHERE agent_tool_phase_map IS NOT NULL;

-- Update the column default to match new Prisma schema
ALTER TABLE "projects" ALTER COLUMN "agent_tool_phase_map" SET DEFAULT '{"query_graph":["informational","exploitation","post_exploitation"],"web_search":["informational","exploitation","post_exploitation"],"execute_curl":["informational","exploitation","post_exploitation"],"execute_naabu":["informational","exploitation","post_exploitation"],"execute_nmap":["informational","exploitation","post_exploitation"],"execute_nuclei":["informational","exploitation","post_exploitation"],"kali_shell":["informational","exploitation","post_exploitation"],"execute_code":["informational","exploitation","post_exploitation"],"execute_hydra":["exploitation","post_exploitation"],"metasploit_console":["exploitation","post_exploitation"],"msf_restart":["exploitation","post_exploitation"]}';
