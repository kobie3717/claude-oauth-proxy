module.exports = {
  apps: [{
    name: "claude-oauth-proxy",
    script: "proxy.mjs",
    cwd: __dirname,
    env_file: ".env",
    watch: false,
    autorestart: true,
    max_restarts: 10,
    restart_delay: 5000,
    log_date_format: "YYYY-MM-DD HH:mm:ss",
    error_file: "logs/error.log",
    out_file: "logs/out.log",
    merge_logs: true,
  }],
};
