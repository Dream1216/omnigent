/** @type {import('next').NextConfig} */
const config = {
  output: "export",
  assetPrefix: "/saas/login-assets",
  poweredByHeader: false,
  reactStrictMode: true,
  // The existing server, not a second Node process, serves the exported page.
  experimental: { cpus: 2 },
};
export default config;
