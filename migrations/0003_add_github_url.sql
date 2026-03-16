-- Add github_url to bounties for stale auto-sync
ALTER TABLE bounties ADD COLUMN github_url TEXT;
CREATE INDEX IF NOT EXISTS idx_bounties_github_url ON bounties(github_url);
