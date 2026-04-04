-- AlterTable: Update Katana and GAU default values
ALTER TABLE "projects" ALTER COLUMN "katana_depth" SET DEFAULT 2;
ALTER TABLE "projects" ALTER COLUMN "katana_max_urls" SET DEFAULT 300;
ALTER TABLE "projects" ALTER COLUMN "katana_timeout" SET DEFAULT 3600;
ALTER TABLE "projects" ALTER COLUMN "gau_enabled" SET DEFAULT false;
