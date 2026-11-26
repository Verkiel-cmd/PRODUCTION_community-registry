export default {
  API_URL: (typeof process !== 'undefined' && process.env && process.env.API_URL)
    ? process.env.API_URL : 'https://production-baranggay-registry.onrender.com'
};