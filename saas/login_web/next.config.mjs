/** @type {import('next').NextConfig} */
const config = {
  output: "export",
  assetPrefix: "/saas/login-assets",
  generateBuildId: async () => {
    const revision = process.env.OMNIGENT_SOURCE_REVISION ?? "";
    return /^[0-9a-f]{40}$/.test(revision) ? revision : "omnigent-login-local";
  },
  poweredByHeader: false,
  reactStrictMode: true,
  // The existing server, not a second Node process, serves the exported page.
  experimental: { cpus: 2 },
};
export default config;
