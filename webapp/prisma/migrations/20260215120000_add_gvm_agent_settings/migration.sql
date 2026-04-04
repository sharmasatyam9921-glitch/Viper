-- Add columns that were previously applied via prisma db push but lacked migrations.
-- This ensures the shadow database matches the production schema.

-- Stealth mode
ALTER TABLE "projects" ADD COLUMN "stealth_mode" BOOLEAN NOT NULL DEFAULT false;

-- GitHub target repos
ALTER TABLE "projects" ADD COLUMN "github_target_repos" TEXT NOT NULL DEFAULT '';

-- Katana enabled toggle
ALTER TABLE "projects" ADD COLUMN "katana_enabled" BOOLEAN NOT NULL DEFAULT true;

-- GVM Vulnerability Scan settings
ALTER TABLE "projects" ADD COLUMN "gvm_scan_config" TEXT NOT NULL DEFAULT 'Full and fast';
ALTER TABLE "projects" ADD COLUMN "gvm_scan_targets" TEXT NOT NULL DEFAULT 'both';
ALTER TABLE "projects" ADD COLUMN "gvm_task_timeout" INTEGER NOT NULL DEFAULT 14400;
ALTER TABLE "projects" ADD COLUMN "gvm_poll_interval" INTEGER NOT NULL DEFAULT 30;
ALTER TABLE "projects" ADD COLUMN "gvm_cleanup_after_scan" BOOLEAN NOT NULL DEFAULT true;

-- Agent Behaviour settings
ALTER TABLE "projects" ADD COLUMN "agent_openai_model" TEXT NOT NULL DEFAULT 'claude-opus-4-6';
ALTER TABLE "projects" ADD COLUMN "agent_informational_system_prompt" TEXT NOT NULL DEFAULT '';
ALTER TABLE "projects" ADD COLUMN "agent_expl_system_prompt" TEXT NOT NULL DEFAULT '';
ALTER TABLE "projects" ADD COLUMN "agent_post_expl_system_prompt" TEXT NOT NULL DEFAULT '';
ALTER TABLE "projects" ADD COLUMN "agent_activate_post_expl_phase" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "projects" ADD COLUMN "agent_post_expl_phase_type" TEXT NOT NULL DEFAULT 'statefull';
ALTER TABLE "projects" ADD COLUMN "agent_lhost" TEXT NOT NULL DEFAULT '';
ALTER TABLE "projects" ADD COLUMN "agent_lport" INTEGER;
ALTER TABLE "projects" ADD COLUMN "agent_bind_port_on_target" INTEGER;
ALTER TABLE "projects" ADD COLUMN "agent_payload_use_https" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "projects" ADD COLUMN "agent_max_iterations" INTEGER NOT NULL DEFAULT 100;
ALTER TABLE "projects" ADD COLUMN "agent_execution_trace_memory_steps" INTEGER NOT NULL DEFAULT 100;
ALTER TABLE "projects" ADD COLUMN "agent_require_approval_for_exploitation" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "projects" ADD COLUMN "agent_require_approval_for_post_exploitation" BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE "projects" ADD COLUMN "agent_tool_output_max_chars" INTEGER NOT NULL DEFAULT 20000;
ALTER TABLE "projects" ADD COLUMN "agent_cypher_max_retries" INTEGER NOT NULL DEFAULT 3;
ALTER TABLE "projects" ADD COLUMN "agent_llm_parse_max_retries" INTEGER NOT NULL DEFAULT 3;
ALTER TABLE "projects" ADD COLUMN "agent_create_graph_image_on_init" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "projects" ADD COLUMN "agent_log_max_mb" INTEGER NOT NULL DEFAULT 10;
ALTER TABLE "projects" ADD COLUMN "agent_log_backup_count" INTEGER NOT NULL DEFAULT 5;
ALTER TABLE "projects" ADD COLUMN "agent_tool_phase_map" JSONB NOT NULL DEFAULT '{"query_graph":["informational","exploitation","post_exploitation"],"web_search":["informational","exploitation","post_exploitation"],"execute_curl":["informational","exploitation","post_exploitation"],"execute_naabu":["informational","exploitation","post_exploitation"],"execute_nmap":["informational","exploitation","post_exploitation"],"execute_nuclei":["informational","exploitation"],"kali_shell":["informational","exploitation"],"execute_code":["exploitation","post_exploitation"],"metasploit_console":["exploitation","post_exploitation"],"msf_restart":["exploitation","post_exploitation"]}';
ALTER TABLE "projects" ADD COLUMN "agent_brute_force_max_wordlist_attempts" INTEGER NOT NULL DEFAULT 3;
ALTER TABLE "projects" ADD COLUMN "agent_bruteforce_speed" INTEGER NOT NULL DEFAULT 5;
