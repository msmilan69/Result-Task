/** @type {import('next').NextConfig} */

module.exports = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'cdn.galaxy.eco' },
      { protocol: 'https', hostname: 'cdn1.p12.games' },
      { protocol: 'https', hostname: 'cdn.p12.games' },
      { protocol: 'https', hostname: 'cdn.galxe.com' },
      { protocol: 'https', hostname: 'cdn-2.galxe.com' },
      { protocol: 'https', hostname: 'd257b89266utxb.cloudfront.net' },
    ],
  },
  reactStrictMode: false,
  async headers() {
    return [
      {
        // Apply these headers to all routes in your application.
        source: '/:path*',
        headers: [{ key: 'X-Frame-Options', value: 'SAMEORIGIN' }],
      },
    ];
  },
};





















