-- AlterTable
ALTER TABLE "projects" ADD COLUMN "ip_mode" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "projects" ADD COLUMN "target_ips" TEXT[] DEFAULT ARRAY[]::TEXT[];
