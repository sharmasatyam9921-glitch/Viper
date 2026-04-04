-- Add phishing / social engineering SMTP configuration
ALTER TABLE "projects" ADD COLUMN "phishing_smtp_config" TEXT NOT NULL DEFAULT '';
